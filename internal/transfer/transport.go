package transfer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	xproxy "golang.org/x/net/proxy"
)

type networkOptions struct {
	mode           string
	proxy          string
	tor            bool
	allowHTTP      bool
	timeout        time.Duration
	attempts       int
	reconnectDelay time.Duration
	onEvent        func(receipt)
	onConnect      func()
	filesystem     *filesystemBrowser
}

type rejectedError struct{ message string }

func (e *rejectedError) Error() string { return e.message }

type pendingResult struct {
	receipt receipt
	err     error
}

type pendingRequest struct {
	digest string
	conn   *wsConnection
	result chan pendingResult
}

type subscription struct {
	id       string
	digest   string
	sequence uint32
}

type controlState struct {
	key      []byte
	sequence uint32
}

type challengeResult struct {
	id  string
	err error
}

type wsConnection struct {
	socket        *websocket.Conn
	writeMu       sync.Mutex
	done          chan struct{}
	challenge     chan challengeResult
	controls      chan []byte
	challengeOnce sync.Once
	closeOnce     sync.Once
}

type Transport struct {
	profile    profile
	options    networkOptions
	endpoint   *url.URL
	signingKey ed25519.PublicKey
	httpClient *http.Client
	dial       func(context.Context, string, string) (net.Conn, error)

	connectMu sync.Mutex
	mu        sync.Mutex
	conn      *wsConnection
	sub       *subscription
	controls  *controlState
	pending   map[string]*pendingRequest
	closed    bool
	ctx       context.Context
	cancel    context.CancelFunc
}

func newTransport(p profile, options networkOptions) (*Transport, error) {
	if options.reconnectDelay <= 0 {
		options.reconnectDelay = 5 * time.Minute
	}
	endpoint, err := validatedEndpoint(p.Endpoint)
	if err != nil {
		return nil, err
	}
	onion := strings.HasSuffix(strings.ToLower(endpoint.Hostname()), ".onion")
	if onion && !options.tor {
		return nil, errors.New("onion endpoints require --tor")
	}
	if (endpoint.Scheme == "http" || endpoint.Scheme == "ws") && !isLoopbackHostname(endpoint.Hostname()) &&
		!(onion && options.tor) && !options.allowHTTP {
		return nil, errors.New("a remote HTTP endpoint requires --allow-http; encrypted payloads and signed receipts are still required")
	}
	proxyAddress := options.proxy
	if proxyAddress == "" && options.tor {
		proxyAddress = "socks5h://127.0.0.1:9050"
	}
	dial, err := networkDialer(proxyAddress, options.timeout)
	if err != nil {
		return nil, err
	}
	signingKey, err := decodePublicSigningKey(p.SigningKey)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	httpTransport := &http.Transport{
		DialContext:     dial,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	client := &http.Client{
		Transport:     httpTransport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	return &Transport{
		profile: p, options: options, endpoint: endpoint, signingKey: signingKey,
		httpClient: client, dial: dial, pending: make(map[string]*pendingRequest), ctx: ctx, cancel: cancel,
	}, nil
}

func networkDialer(proxyAddress string, timeout time.Duration) (func(context.Context, string, string) (net.Conn, error), error) {
	direct := &net.Dialer{Timeout: timeout}
	if proxyAddress == "" {
		return direct.DialContext, nil
	}
	parsed, err := url.Parse(proxyAddress)
	if err != nil || parsed.Scheme != "socks5h" || parsed.Host == "" {
		return nil, errors.New("use socks5h:// so destination DNS is resolved by the proxy")
	}
	var auth *xproxy.Auth
	if parsed.User != nil {
		password, _ := parsed.User.Password()
		auth = &xproxy.Auth{User: parsed.User.Username(), Password: password}
	}
	proxyDialer, err := xproxy.SOCKS5("tcp", parsed.Host, auth, direct)
	if err != nil {
		return nil, err
	}
	if contextDialer, ok := proxyDialer.(xproxy.ContextDialer); ok {
		return contextDialer.DialContext, nil
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		type result struct {
			conn net.Conn
			err  error
		}
		resultChannel := make(chan result, 1)
		go func() {
			conn, err := proxyDialer.Dial(network, address)
			resultChannel <- result{conn: conn, err: err}
		}()
		select {
		case value := <-resultChannel:
			return value.conn, value.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}, nil
}

func websocketURL(input *url.URL) string {
	copy := *input
	if copy.Scheme == "http" {
		copy.Scheme = "ws"
	} else if copy.Scheme == "https" {
		copy.Scheme = "wss"
	}
	return copy.String()
}

func httpURL(input *url.URL) string {
	copy := *input
	if copy.Scheme == "ws" {
		copy.Scheme = "http"
	} else if copy.Scheme == "wss" {
		copy.Scheme = "https"
	}
	return copy.String()
}

func (t *Transport) validAck(value receipt, request, frameDigest string) error {
	delta := time.Now().UnixMilli() - value.At
	if delta < 0 {
		delta = -delta
	}
	if value.Kind != "ack" || value.ID != request || value.Digest != frameDigest ||
		delta > (requestLifetime+30*time.Second).Milliseconds() {
		return errors.New("receipt does not match this request")
	}
	return nil
}

func (t *Transport) post(frame []byte, request string) (receipt, error) {
	ctx, cancel := context.WithTimeout(t.ctx, t.options.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, httpURL(t.endpoint), bytes.NewReader(frame))
	if err != nil {
		return receipt{}, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = int64(len(frame))
	response, err := t.httpClient.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return receipt{}, errors.New("request timed out")
		}
		return receipt{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return receipt{}, fmt.Errorf("endpoint rejected the request (%d)", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, receiptBytes+1))
	if err != nil {
		return receipt{}, err
	}
	if len(body) != receiptBytes {
		return receipt{}, errors.New("invalid server receipt")
	}
	value, err := parseReceipt(t.signingKey, body)
	if err != nil {
		return receipt{}, err
	}
	if err := t.validAck(value, request, digest(frame)); err != nil {
		return receipt{}, err
	}
	return value, nil
}

func (t *Transport) Connect() error {
	t.connectMu.Lock()
	defer t.connectMu.Unlock()
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return errors.New("client is closed")
	}
	if t.conn != nil && t.sub != nil {
		select {
		case <-t.conn.done:
		default:
			t.mu.Unlock()
			return nil
		}
	}
	t.mu.Unlock()
	return t.openSocket()
}

func (t *Transport) openSocket() error {
	dialer := websocket.Dialer{
		NetDialContext:    t.dial,
		HandshakeTimeout:  t.options.timeout,
		EnableCompression: false,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
	}
	ctx, cancel := context.WithTimeout(t.ctx, t.options.timeout)
	defer cancel()
	socket, response, err := dialer.DialContext(ctx, websocketURL(t.endpoint), nil)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		return err
	}
	socket.SetReadLimit(maxFrameBytes)
	connection := &wsConnection{
		socket: socket, done: make(chan struct{}), challenge: make(chan challengeResult, 1), controls: make(chan []byte, 16),
	}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		_ = socket.Close()
		return errors.New("client is closed")
	}
	t.conn = connection
	t.sub = nil
	if t.controls != nil {
		clear(t.controls.key)
	}
	t.controls = nil
	t.mu.Unlock()
	go t.readLoop(connection)
	go t.controlLoop(connection)

	var challenge string
	select {
	case result := <-connection.challenge:
		if result.err != nil {
			t.terminate(connection, result.err)
			return result.err
		}
		challenge = result.id
	case <-time.After(t.options.timeout):
		err := errors.New("server handshake timed out")
		t.terminate(connection, err)
		return err
	case <-t.ctx.Done():
		t.terminate(connection, errors.New("client is closed"))
		return errors.New("client is closed")
	case <-connection.done:
		return errors.New("connection closed")
	}

	operation := map[string]any{"type": "subscribe", "challenge": challenge}
	var controls *controlState
	if t.options.filesystem != nil {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			t.terminate(connection, err)
			return err
		}
		controls = &controlState{key: key}
		operation["browse"] = browseHello(key, t.options.filesystem)
	}
	record, err := newRecord(t.profile.Token, operation)
	if err != nil {
		t.terminate(connection, err)
		return err
	}
	key, err := decodePublicEncryptionKey(t.profile.EncryptionKey)
	if err != nil {
		t.terminate(connection, err)
		return err
	}
	frame, err := sealRecord(key, record, nil)
	if err != nil {
		t.terminate(connection, err)
		return err
	}
	t.mu.Lock()
	if t.conn != connection {
		t.mu.Unlock()
		clear(frame)
		return errors.New("connection closed")
	}
	t.controls = controls
	t.sub = &subscription{id: record.ID, digest: digest(frame)}
	t.mu.Unlock()
	ack, err := t.sendSocket(connection, frame, record.ID)
	clear(frame)
	if err != nil {
		t.terminate(connection, err)
		return err
	}
	if ack.Code != codeOK {
		err := &rejectedError{message: "server rejected the subscription"}
		t.terminate(connection, err)
		return err
	}
	if t.options.onConnect != nil {
		t.options.onConnect()
	}
	return nil
}

func (t *Transport) readLoop(connection *wsConnection) {
	for {
		messageType, frame, err := connection.socket.ReadMessage()
		if err != nil {
			t.terminate(connection, errors.New("connection closed"))
			return
		}
		if messageType != websocket.BinaryMessage {
			t.terminate(connection, errors.New("invalid server receipt"))
			return
		}
		if len(frame) != receiptBytes {
			controlFrame := append([]byte(nil), frame...)
			select {
			case connection.controls <- controlFrame:
			case <-connection.done:
				return
			}
			continue
		}
		value, err := parseReceipt(t.signingKey, frame)
		if err != nil {
			t.terminate(connection, err)
			return
		}
		t.mu.Lock()
		if t.conn != connection {
			t.mu.Unlock()
			return
		}
		if value.Code == codeChallenge && t.sub == nil {
			delta := time.Now().UnixMilli() - value.At
			if delta < 0 {
				delta = -delta
			}
			valid := value.Kind == "event" && value.Sequence == 0 && value.Digest == strings.Repeat("0", 64) && delta <= 30_000
			t.mu.Unlock()
			if !valid {
				t.terminate(connection, errors.New("invalid server challenge"))
				return
			}
			connection.challengeOnce.Do(func() { connection.challenge <- challengeResult{id: value.ID} })
			continue
		}
		if value.Kind == "ack" {
			pending := t.pending[value.ID]
			if pending == nil || pending.conn != connection {
				t.mu.Unlock()
				continue
			}
			if err := t.validAck(value, value.ID, pending.digest); err != nil {
				t.mu.Unlock()
				t.terminate(connection, err)
				return
			}
			delete(t.pending, value.ID)
			t.mu.Unlock()
			pending.result <- pendingResult{receipt: value}
			continue
		}
		current := t.sub
		if current == nil {
			t.mu.Unlock()
			t.terminate(connection, errors.New("invalid or replayed live event"))
			return
		}
		delta := time.Now().UnixMilli() - value.At
		if delta < 0 {
			delta = -delta
		}
		if value.ID != current.id || value.Digest != current.digest || value.Sequence != current.sequence+1 || delta > 30_000 {
			t.mu.Unlock()
			t.terminate(connection, errors.New("invalid or replayed live event"))
			return
		}
		current.sequence = value.Sequence
		onEvent := t.options.onEvent
		t.mu.Unlock()
		if onEvent != nil {
			onEvent(value)
		}
	}
}

func (t *Transport) controlLoop(connection *wsConnection) {
	for {
		select {
		case frame := <-connection.controls:
			if err := t.receiveControl(connection, frame); err != nil {
				t.terminate(connection, err)
				return
			}
		case <-connection.done:
			return
		}
	}
}

func (t *Transport) receiveControl(connection *wsConnection, frame []byte) error {
	t.mu.Lock()
	if t.conn != connection || t.sub == nil || t.controls == nil || t.options.filesystem == nil {
		t.mu.Unlock()
		return errors.New("filesystem browsing is not enabled")
	}
	subID, subDigest := t.sub.id, t.sub.digest
	controls := t.controls
	browser := t.options.filesystem
	keyCopy := append([]byte(nil), controls.key...)
	t.mu.Unlock()
	defer clear(keyCopy)
	command, err := openCommand(keyCopy, t.signingKey, subID, subDigest, frame)
	if err != nil {
		return err
	}
	t.mu.Lock()
	if t.conn != connection || t.sub == nil || t.sub.id != subID || t.controls != controls {
		t.mu.Unlock()
		return nil
	}
	if command.Sequence != controls.sequence+1 {
		t.mu.Unlock()
		return errors.New("replayed or out-of-order filesystem control")
	}
	controls.sequence = command.Sequence
	t.mu.Unlock()
	var result any
	if command.Query.Type == "download" {
		result = t.downloadFromClient(connection, command, browser)
	} else {
		result = browser.query(command.Query)
	}

	t.mu.Lock()
	validConnection := t.conn == connection && t.sub != nil && t.sub.id == subID && t.sub.digest == subDigest
	t.mu.Unlock()
	if !validConnection {
		return nil
	}
	record, err := newRecord(t.profile.Token, map[string]any{
		"type": "browse-result", "job": command.ID, "result": result,
	})
	if err != nil {
		return err
	}
	recipient, err := decodePublicEncryptionKey(t.profile.EncryptionKey)
	if err != nil {
		return err
	}
	reply, err := sealRecord(recipient, record, nil)
	if err != nil {
		return err
	}
	defer clear(reply)
	t.mu.Lock()
	validConnection = t.conn == connection && t.sub != nil && t.sub.id == subID && t.sub.digest == subDigest
	t.mu.Unlock()
	if !validConnection {
		return nil
	}
	_, err = t.sendSocket(connection, reply, record.ID)
	return err
}

func (t *Transport) sendSocket(connection *wsConnection, frame []byte, request string) (receipt, error) {
	pending := &pendingRequest{
		digest: digest(frame), conn: connection, result: make(chan pendingResult, 1),
	}
	t.mu.Lock()
	if t.closed || t.conn != connection {
		t.mu.Unlock()
		return receipt{}, errors.New("connection closed")
	}
	t.pending[request] = pending
	t.mu.Unlock()

	connection.writeMu.Lock()
	_ = connection.socket.SetWriteDeadline(time.Now().Add(t.options.timeout))
	err := connection.socket.WriteMessage(websocket.BinaryMessage, frame)
	connection.writeMu.Unlock()
	if err != nil {
		t.removePending(request, pending)
		t.terminate(connection, err)
		return receipt{}, err
	}
	timer := time.NewTimer(t.options.timeout)
	defer timer.Stop()
	select {
	case result := <-pending.result:
		return result.receipt, result.err
	case <-timer.C:
		select {
		case result := <-pending.result:
			return result.receipt, result.err
		default:
		}
		t.removePending(request, pending)
		err := errors.New("request timed out")
		t.terminate(connection, err)
		return receipt{}, err
	case <-connection.done:
		select {
		case result := <-pending.result:
			return result.receipt, result.err
		default:
		}
		t.removePending(request, pending)
		return receipt{}, errors.New("connection closed")
	case <-t.ctx.Done():
		select {
		case result := <-pending.result:
			return result.receipt, result.err
		default:
		}
		t.removePending(request, pending)
		return receipt{}, errors.New("client is closed")
	}
}

func (t *Transport) removePending(request string, expected *pendingRequest) {
	t.mu.Lock()
	if t.pending[request] == expected {
		delete(t.pending, request)
	}
	t.mu.Unlock()
}

func (t *Transport) terminate(connection *wsConnection, cause error) {
	connection.closeOnce.Do(func() {
		_ = connection.socket.Close()
		close(connection.done)
		connection.challengeOnce.Do(func() {
			connection.challenge <- challengeResult{err: cause}
		})
		t.mu.Lock()
		if t.conn == connection {
			t.conn = nil
			t.sub = nil
			if t.controls != nil {
				clear(t.controls.key)
			}
			t.controls = nil
		}
		failed := make([]*pendingRequest, 0)
		for id, pending := range t.pending {
			if pending.conn == connection {
				delete(t.pending, id)
				failed = append(failed, pending)
			}
		}
		t.mu.Unlock()
		for _, pending := range failed {
			pending.result <- pendingResult{err: cause}
		}
	})
}

func (t *Transport) Send(frame []byte, request string) (receipt, error) {
	if len(frame) > maxFrameBytes {
		return receipt{}, errors.New("invalid record")
	}
	var last error = errors.New("unable to submit request")
	for attempt := 0; attempt < t.options.attempts; attempt++ {
		t.mu.Lock()
		closed := t.closed
		t.mu.Unlock()
		if closed {
			return receipt{}, errors.New("client is closed")
		}
		var value receipt
		var err error
		if t.options.mode == "http" {
			value, err = t.post(frame, request)
		} else {
			err = t.Connect()
			if err == nil {
				t.mu.Lock()
				connection := t.conn
				t.mu.Unlock()
				if connection == nil {
					err = errors.New("connection closed")
				} else {
					value, err = t.sendSocket(connection, frame, request)
				}
			}
		}
		if err == nil {
			if value.Code == codeRejected || value.Code == codeNotFound {
				return receipt{}, &rejectedError{message: "server rejected the operation"}
			}
			if value.Code == codeBusy {
				err = errors.New("server busy")
			} else {
				return value, nil
			}
		}
		var rejected *rejectedError
		if errors.As(err, &rejected) {
			return receipt{}, err
		}
		last = err
		if attempt+1 < t.options.attempts {
			delay := 250 * time.Millisecond * time.Duration(1<<attempt)
			if delay > 4*time.Second {
				delay = 4 * time.Second
			}
			var randomByte [1]byte
			_, _ = rand.Read(randomByte[:])
			delay += time.Duration(randomByte[0]%100) * time.Millisecond
			select {
			case <-time.After(delay):
			case <-t.ctx.Done():
				return receipt{}, errors.New("client is closed")
			}
		}
	}
	return receipt{}, last
}

func (t *Transport) Watch(ctx context.Context) error {
	if t.options.mode != "ws" {
		return errors.New("live updates require WebSocket mode")
	}
	for {
		select {
		case <-ctx.Done():
			t.Close()
			return nil
		case <-t.ctx.Done():
			return nil
		default:
		}
		err := t.Connect()
		if err == nil {
			t.mu.Lock()
			connection := t.conn
			t.mu.Unlock()
			if connection != nil {
				select {
				case <-connection.done:
				case <-ctx.Done():
					t.Close()
					return nil
				case <-t.ctx.Done():
					return nil
				}
			}
		} else {
			var rejected *rejectedError
			if errors.As(err, &rejected) {
				return err
			}
		}
		select {
		case <-time.After(t.options.reconnectDelay):
		case <-ctx.Done():
			t.Close()
			return nil
		case <-t.ctx.Done():
			return nil
		}
	}
}

func (t *Transport) Close() {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	connection := t.conn
	t.mu.Unlock()
	t.cancel()
	if connection != nil {
		t.terminate(connection, errors.New("client is closed"))
	}
	if transport, ok := t.httpClient.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}
