package transfer

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/net/netutil"
)

type serverOptions struct {
	state    string
	host     string
	port     int
	pathname string
	maxBytes int64
}

type serverSubscription struct {
	owner, id, digest string
	sequence          uint32
	browse            *serverBrowseState
}

type serverConnection struct {
	socket      *websocket.Conn
	challenge   string
	connectedAt time.Time
	sub         *serverSubscription // guarded by server.mu
	outgoing    chan []byte
	done        chan struct{}
	once        sync.Once
}

func (c *serverConnection) stop() { c.once.Do(func() { close(c.done); _ = c.socket.Close() }) }
func (c *serverConnection) send(frame []byte) bool {
	select {
	case <-c.done:
		return false
	default:
	}
	select {
	case c.outgoing <- frame:
		return true
	default:
		c.stop()
		return false
	}
}

type remoteClient struct {
	ID, Name, Cwd, Platform     string
	ConnectedAt                 time.Time
	Browsing, Preview, Download bool
}

type server struct {
	mu          sync.Mutex
	private     *ecdh.PrivateKey
	signing     ed25519.PrivateKey
	tokenHash   []byte
	storage     *storage
	http        *http.Server
	listener    net.Listener
	url         string
	connections map[*serverConnection]struct{}
	jobs        map[string]*browseJob
	updates     chan struct{}
	gate        chan struct{}
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	closed      sync.Once
	stopped     bool
}

var pingPath = regexp.MustCompile(`^/(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{8}(?:-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12})/ping$`)

func startServer(options serverOptions) (*server, error) {
	if options.host == "" {
		options.host = "127.0.0.1"
	}
	if options.pathname == "" {
		options.pathname = "/"
	}
	if !strings.HasPrefix(options.pathname, "/") || strings.ContainsAny(options.pathname, "?#") {
		return nil, errors.New("invalid endpoint path")
	}
	if options.maxBytes == 0 {
		options.maxBytes = 1024 * 1024 * 1024
	}
	root, err := privateDirectory(options.state)
	if err != nil {
		return nil, err
	}
	keys, private, signing, err := loadServerKeys(root)
	if err != nil {
		return nil, err
	}
	store, err := newStorage(root, options.maxBytes)
	if err != nil {
		return nil, err
	}
	if err := store.cleanReceipts(time.Now().UnixMilli()); err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(options.host, strconv.Itoa(options.port)))
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	tokenHash, _ := hex.DecodeString(keys.TokenHash)
	s := &server{private: private, signing: signing, tokenHash: tokenHash, storage: store, listener: netutil.LimitListener(listener, 128),
		connections: make(map[*serverConnection]struct{}), jobs: make(map[string]*browseJob), updates: make(chan struct{}, 1), gate: make(chan struct{}, 64), ctx: ctx, cancel: cancel}
	s.url = "http://" + listener.Addr().String() + options.pathname
	s.http = &http.Server{ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 16 * 1024,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.serveHTTP(options.pathname, w, r) })}
	s.wg.Add(1)
	go s.background()
	go func() { _ = s.http.Serve(s.listener) }()
	return s, nil
}

func (s *server) notify() {
	select {
	case s.updates <- struct{}{}:
	default:
	}
}

func (s *server) serveHTTP(pathname string, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	s.mu.Lock()
	stopped := s.stopped
	s.mu.Unlock()
	if stopped {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && pingPath.MatchString(r.RequestURI) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.RequestURI != pathname {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if websocket.IsWebSocketUpgrade(r) {
		if r.Header.Get("Sec-WebSocket-Protocol") != "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		s.serveSocket(w, r)
		return
	}
	if r.Method != http.MethodPost || r.ContentLength > maxFrameBytes {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFrameBytes)
	defer r.Body.Close()
	frame, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	reply, err := s.handle(frame, nil)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(reply)
}

func (s *server) ack(record incomingRecord, binding string, result transferResult) ([]byte, error) {
	return signReceipt(s.signing, receipt{Kind: "ack", Code: result.Code, ID: record.ID, Digest: binding, At: time.Now().UnixMilli(), Transfer: result.Transfer, Bytes: result.Bytes, Index: result.Index, Offset: result.Offset})
}

func (s *server) broadcast(owner string, result transferResult) {
	for c := range s.connections {
		sub := c.sub
		if sub == nil || sub.owner != owner {
			continue
		}
		if sub.sequence == ^uint32(0) {
			c.stop()
			continue
		}
		sub.sequence++
		frame, err := signReceipt(s.signing, receipt{Kind: "event", Code: result.Code, ID: sub.id, Digest: sub.digest, At: time.Now().UnixMilli(), Transfer: result.Transfer, Bytes: result.Bytes, Index: result.Index, Offset: result.Offset, Sequence: sub.sequence})
		if err != nil {
			c.stop()
			continue
		}
		c.send(frame)
	}
	s.notify()
}

func (s *server) handle(frame []byte, c *serverConnection) ([]byte, error) {
	select {
	case s.gate <- struct{}{}:
		defer func() { <-s.gate }()
	default:
		return nil, errors.New("server busy")
	}
	record, data, err := openRecord(s.private, frame)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	now := time.Now().UnixMilli()
	hash, _ := hex.DecodeString(digest([]byte(record.Token)))
	if record.Expires <= now || record.Expires > now+requestLifetime.Milliseconds()+30_000 || subtle.ConstantTimeCompare(hash, s.tokenHash) != 1 {
		return nil, errors.New("not authorized")
	}
	owner, binding := hex.EncodeToString(hash), digest(frame)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return nil, errors.New("server stopped")
	}
	op := record.Operation
	subscribing := op.Type == "subscribe"
	if (subscribing && (c == nil || c.sub != nil || op.Challenge != c.challenge || !idPattern.MatchString(op.Challenge))) || (c != nil && !subscribing && c.sub == nil) {
		return s.ack(record, binding, transferResult{Code: codeRejected})
	}
	cached, err := s.storage.cached(record.ID)
	if err != nil {
		return nil, err
	}
	if cached != nil {
		if subscribing || cached.Digest != binding {
			return nil, errors.New("replayed or conflicting request")
		}
		return base64.RawURLEncoding.DecodeString(cached.Receipt)
	}
	var completedJob *browseJob
	var browseValue any
	var transferJob *browseJob
	result, operationErr := func() (transferResult, error) {
		if op.Type == "browse-result" {
			completedJob = s.jobs[op.Job]
			if c == nil || len(data) != 0 || !idPattern.MatchString(op.Job) || completedJob == nil || completedJob.connection != c || c.sub == nil || completedJob.subscription != c.sub.id {
				return transferResult{}, errors.New("unsolicited filesystem response")
			}
			browseValue, err = decodeBrowseResult(op.Result)
			if err != nil {
				return transferResult{}, err
			}
			kind := resultType(browseValue)
			if completedJob.query.Type == "download" && kind != "error" {
				value, ok := browseValue.(browseDownloadResult)
				if !ok || value.Transfer != completedJob.query.Transfer {
					return transferResult{}, errors.New("wrong download result")
				}
				verified, err := s.storage.execute(record.ID, owner, operation{Type: "status", Transfer: value.Transfer}, nil)
				if err != nil || verified.Code != codeComplete || verified.Bytes != uint64(value.Bytes) || verified.Index != uint32(value.Entries) {
					return transferResult{}, errors.New("download is not verified")
				}
			} else if kind != "error" && kind != completedJob.query.Type {
				return transferResult{}, errors.New("unexpected filesystem response")
			}
			return transferResult{Transfer: op.Job}, nil
		}
		if op.Type == "begin" || op.Type == "chunk" || op.Type == "commit" {
			reserved := false
			for _, job := range s.jobs {
				if job.query.Type == "download" && job.query.Transfer == op.Transfer {
					reserved = true
					break
				}
			}
			if op.Job != "" || reserved {
				transferJob = s.jobs[op.Job]
				if c == nil || !idPattern.MatchString(op.Job) || transferJob == nil || transferJob.connection != c || c.sub == nil || transferJob.subscription != c.sub.id || transferJob.query.Type != "download" || transferJob.query.Transfer != op.Transfer {
					return transferResult{}, errors.New("wrong download source")
				}
			}
		}
		if subscribing && op.Browse != nil {
			if err := validateHello(op.Browse); err != nil {
				return transferResult{}, err
			}
		}
		return s.storage.execute(record.ID, owner, op, data)
	}()
	if operationErr != nil {
		result = transferResult{Code: codeRejected}
	}
	signed, err := s.ack(record, binding, result)
	if err != nil {
		return nil, err
	}
	if err := s.storage.cache(record.ID, storedReceipt{Digest: binding, Expires: record.Expires, Receipt: base64RawURL(signed)}); err != nil {
		return nil, err
	}
	if subscribing && result.Code == codeOK {
		c.sub = &serverSubscription{owner: owner, id: record.ID, digest: binding}
		if op.Browse != nil {
			key, _ := base64.RawURLEncoding.DecodeString(op.Browse.Key)
			c.sub.browse = &serverBrowseState{hello: *op.Browse, key: key}
		}
		s.notify()
	} else if op.Type == "browse-result" && completedJob != nil && browseValue != nil && result.Code == codeOK {
		delete(s.jobs, op.Job)
		completedJob.reply <- browseReply{value: browseValue}
	} else if result.Code <= codeComplete && op.Type != "status" && op.Type != "browse-result" {
		if transferJob != nil {
			transferJob.lastActivity = time.Now()
			if op.Type == "begin" {
				for _, entry := range op.Entries {
					transferJob.total += uint64(entry.Size)
				}
			}
			select {
			case transferJob.progress <- transferProgress{bytes: result.Bytes, total: transferJob.total}:
			default:
			}
		}
		s.broadcast(owner, result)
	}
	return signed, nil
}

func (s *server) serveSocket(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	full := s.stopped || len(s.connections) >= 128
	s.mu.Unlock()
	if full {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	upgrader := websocket.Upgrader{EnableCompression: false, CheckOrigin: func(*http.Request) bool { return true }, HandshakeTimeout: 10 * time.Second}
	socket, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	challenge, err := newID()
	if err != nil {
		_ = socket.Close()
		return
	}
	c := &serverConnection{socket: socket, challenge: challenge, connectedAt: time.Now(), outgoing: make(chan []byte, 64), done: make(chan struct{})}
	s.mu.Lock()
	if s.stopped || len(s.connections) >= 128 {
		s.mu.Unlock()
		c.stop()
		return
	}
	s.connections[c] = struct{}{}
	s.wg.Add(2)
	s.mu.Unlock()
	defer s.wg.Done()
	defer s.disconnect(c)
	socket.SetReadLimit(maxFrameBytes)
	_ = socket.SetReadDeadline(time.Now().Add(10 * time.Second))
	socket.SetPongHandler(func(string) error { return socket.SetReadDeadline(time.Now().Add(60 * time.Second)) })
	go func() {
		defer s.wg.Done()
		defer c.stop()
		for {
			select {
			case frame := <-c.outgoing:
				_ = socket.SetWriteDeadline(time.Now().Add(15 * time.Second))
				if err := socket.WriteMessage(websocket.BinaryMessage, frame); err != nil {
					return
				}
			case <-c.done:
				return
			}
		}
	}()
	frame, err := signReceipt(s.signing, receipt{Kind: "event", Code: codeChallenge, ID: challenge, Digest: strings.Repeat("0", 64), At: time.Now().UnixMilli()})
	if err != nil || !c.send(frame) {
		return
	}
	for {
		kind, frame, err := socket.ReadMessage()
		if err != nil || kind != websocket.BinaryMessage {
			return
		}
		reply, err := s.handle(frame, c)
		if err != nil || !c.send(reply) {
			return
		}
		s.mu.Lock()
		authenticated := c.sub != nil
		s.mu.Unlock()
		if authenticated {
			_ = socket.SetReadDeadline(time.Now().Add(60 * time.Second))
		}
	}
}

func (s *server) disconnect(c *serverConnection) {
	c.stop()
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.connections, c)
	if c.sub != nil && c.sub.browse != nil {
		clear(c.sub.browse.key)
	}
	for id, job := range s.jobs {
		if job.connection == c {
			delete(s.jobs, id)
			job.reply <- browseReply{err: errors.New("client disconnected")}
		}
	}
	s.notify()
}

func (s *server) background() {
	defer s.wg.Done()
	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()
	cleanup := time.NewTicker(time.Minute)
	defer cleanup.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-cleanup.C:
			s.mu.Lock()
			_ = s.storage.cleanReceipts(time.Now().UnixMilli())
			s.mu.Unlock()
		case <-heartbeat.C:
			s.mu.Lock()
			peers := make([]*serverConnection, 0, len(s.connections))
			for c := range s.connections {
				peers = append(peers, c)
			}
			s.mu.Unlock()
			for _, c := range peers {
				if err := c.socket.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)); err != nil {
					c.stop()
				}
			}
		}
	}
}

func (s *server) clients() []remoteClient {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]remoteClient, 0, len(s.connections))
	for c := range s.connections {
		sub := c.sub
		if sub == nil {
			continue
		}
		peer := remoteClient{ID: sub.id, Name: "Client " + sub.id[:8], ConnectedAt: c.connectedAt}
		if sub.browse != nil {
			h := sub.browse.hello
			peer.Browsing = true
			peer.Cwd = h.Cwd
			peer.Platform = h.Platform
			if h.Name != "" {
				peer.Name = h.Name
			}
			for _, capability := range h.Capabilities {
				if capability == "preview" {
					peer.Preview = true
				}
				if capability == "download" {
					peer.Download = true
				}
			}
		}
		result = append(result, peer)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ConnectedAt.Before(result[j].ConnectedAt) })
	return result
}

func (s *server) close() error {
	var result error
	s.closed.Do(func() {
		s.mu.Lock()
		s.stopped = true
		s.cancel()
		for c := range s.connections {
			c.stop()
		}
		s.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		result = s.http.Shutdown(ctx)
		if result != nil {
			_ = s.http.Close()
		}
		s.wg.Wait()
	})
	return result
}
