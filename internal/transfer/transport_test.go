package transfer

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWebSocketHandshakeAndMessageDeliveryOverPipe(t *testing.T) {
	recipientPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingPublic, signingPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingDER, err := x509.MarshalPKIXPublicKey(signingPublic)
	if err != nil {
		t.Fatal(err)
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		t.Fatal(err)
	}
	p := profile{
		V: 1, EncryptionKey: base64.RawURLEncoding.EncodeToString(recipientPrivate.PublicKey().Bytes()),
		SigningKey: base64.RawURLEncoding.EncodeToString(signingDER),
		Token:      base64.RawURLEncoding.EncodeToString(token), Endpoint: "ws://server.example/socket",
	}
	transport, err := newTransport(p, networkOptions{
		mode: "ws", allowHTTP: true, timeout: 2 * time.Second, attempts: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	clientSide, serverSide := net.Pipe()
	var dialMu sync.Mutex
	dialed := false
	transport.dial = func(_ context.Context, _, _ string) (net.Conn, error) {
		dialMu.Lock()
		defer dialMu.Unlock()
		if dialed {
			return nil, errors.New("unexpected reconnect")
		}
		dialed = true
		return clientSide, nil
	}
	serverResult := make(chan error, 1)
	go func() {
		serverResult <- serveTestWebSocket(serverSide, recipientPrivate, signingPrivate)
	}()
	if err := transport.Connect(); err != nil {
		select {
		case serverErr := <-serverResult:
			t.Fatalf("connect failed: %v (server: %v)", err, serverErr)
		default:
			t.Fatal(err)
		}
	}
	result, err := sendMessage(transport, "hello from Go")
	if err != nil {
		t.Fatal(err)
	}
	if result.Code != codeComplete || result.Bytes != uint64(len("hello from Go")) {
		t.Fatalf("unexpected message receipt: %#v", result)
	}
	select {
	case err := <-serverResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("test WebSocket server did not finish")
	}
}

func serveTestWebSocket(conn net.Conn, recipientPrivate *ecdh.PrivateKey, signingPrivate ed25519.PrivateKey) error {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	request, err := http.ReadRequest(reader)
	if err != nil {
		return err
	}
	_ = request.Body.Close()
	websocketKey := request.Header.Get("Sec-WebSocket-Key")
	if websocketKey == "" || !strings.EqualFold(request.Header.Get("Upgrade"), "websocket") {
		return errors.New("invalid WebSocket upgrade")
	}
	acceptHash := sha1.Sum([]byte(websocketKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	response := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " +
		base64.StdEncoding.EncodeToString(acceptHash[:]) + "\r\n\r\n"
	if _, err := io.WriteString(conn, response); err != nil {
		return err
	}
	challengeID := "00112233445566778899aabbccddeeff"
	challenge, err := testReceipt(signingPrivate, 1, codeChallenge, challengeID, strings.Repeat("0", 64), 0, 0)
	if err != nil {
		return err
	}
	if err := writeTestWebSocketFrame(conn, challenge); err != nil {
		return err
	}
	subscribeFrame, err := readTestWebSocketFrame(reader)
	if err != nil {
		return err
	}
	subscribe, _, err := openTestRecord(recipientPrivate, subscribeFrame)
	if err != nil {
		return fmt.Errorf("open subscription: %w", err)
	}
	subscribeOperation, ok := subscribe.Operation.(map[string]any)
	if !ok || subscribeOperation["type"] != "subscribe" || subscribeOperation["challenge"] != challengeID {
		return fmt.Errorf("invalid subscription: %#v", subscribe.Operation)
	}
	ack, err := testReceipt(signingPrivate, 0, codeOK, subscribe.ID, digest(subscribeFrame), 0, 0)
	if err != nil {
		return err
	}
	if err := writeTestWebSocketFrame(conn, ack); err != nil {
		return err
	}
	messageFrame, err := readTestWebSocketFrame(reader)
	if err != nil {
		return err
	}
	message, _, err := openTestRecord(recipientPrivate, messageFrame)
	if err != nil {
		return fmt.Errorf("open message: %w", err)
	}
	messageOperation, ok := message.Operation.(map[string]any)
	if !ok || messageOperation["type"] != "message" || messageOperation["text"] != "hello from Go" {
		return fmt.Errorf("invalid message: %#v", message.Operation)
	}
	ack, err = testReceipt(signingPrivate, 0, codeComplete, message.ID, digest(messageFrame), uint64(len("hello from Go")), 0)
	if err != nil {
		return err
	}
	return writeTestWebSocketFrame(conn, ack)
}

func openTestRecord(privateKey *ecdh.PrivateKey, frame []byte) (wireRecord, []byte, error) {
	if len(frame) < blockBytes+48 || (len(frame)-48)%blockBytes != 0 {
		return wireRecord{}, nil, errors.New("invalid record")
	}
	ephemeral, err := ecdh.X25519().NewPublicKey(frame[:32])
	if err != nil {
		return wireRecord{}, nil, err
	}
	sharedDH, err := privateKey.ECDH(ephemeral)
	if err != nil {
		return wireRecord{}, nil, err
	}
	kemSuiteID := append([]byte("KEM"), 0x00, 0x20)
	eaePRK, err := labeledExtract(kemSuiteID, nil, "eae_prk", sharedDH)
	if err != nil {
		return wireRecord{}, nil, err
	}
	kemContext := append(append([]byte(nil), frame[:32]...), privateKey.PublicKey().Bytes()...)
	sharedSecret, err := labeledExpand(kemSuiteID, eaePRK, "shared_secret", kemContext, 32)
	if err != nil {
		return wireRecord{}, nil, err
	}
	hpkeSuiteID := append([]byte("HPKE"), 0x00, 0x20, 0x00, 0x01, 0x00, 0x02)
	pskIDHash, err := labeledExtract(hpkeSuiteID, nil, "psk_id_hash", nil)
	if err != nil {
		return wireRecord{}, nil, err
	}
	infoHash, err := labeledExtract(hpkeSuiteID, nil, "info_hash", requestInfo)
	if err != nil {
		return wireRecord{}, nil, err
	}
	keyContext := append(append([]byte{0}, pskIDHash...), infoHash...)
	secret, err := labeledExtract(hpkeSuiteID, sharedSecret, "secret", nil)
	if err != nil {
		return wireRecord{}, nil, err
	}
	key, err := labeledExpand(hpkeSuiteID, secret, "key", keyContext, 32)
	if err != nil {
		return wireRecord{}, nil, err
	}
	nonce, err := labeledExpand(hpkeSuiteID, secret, "base_nonce", keyContext, 12)
	if err != nil {
		return wireRecord{}, nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return wireRecord{}, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return wireRecord{}, nil, err
	}
	plaintext, err := aead.Open(nil, nonce, frame[32:], requestInfo)
	if err != nil {
		return wireRecord{}, nil, err
	}
	if len(plaintext) < 4 {
		return wireRecord{}, nil, errors.New("invalid record")
	}
	headerLength := int(binary.BigEndian.Uint32(plaintext[:4]))
	if headerLength < 2 || 4+headerLength > len(plaintext) {
		return wireRecord{}, nil, errors.New("invalid record")
	}
	var record wireRecord
	if err := json.Unmarshal(plaintext[4:4+headerLength], &record); err != nil {
		return wireRecord{}, nil, err
	}
	if record.Length < 0 || 4+headerLength+record.Length > len(plaintext) {
		return wireRecord{}, nil, errors.New("invalid record")
	}
	data := append([]byte(nil), plaintext[4+headerLength:4+headerLength+record.Length]...)
	return record, data, nil
}

func testReceipt(signingKey ed25519.PrivateKey, kind byte, code uint16, id, frameDigest string, bytesValue uint64, sequence uint32) ([]byte, error) {
	idBytes, err := hex.DecodeString(id)
	if err != nil || len(idBytes) != 16 {
		return nil, errors.New("invalid receipt id")
	}
	digestBytes, err := hex.DecodeString(frameDigest)
	if err != nil || len(digestBytes) != 32 {
		return nil, errors.New("invalid receipt digest")
	}
	payload := make([]byte, receiptPayloadLen)
	payload[0] = 1
	payload[1] = kind
	binary.BigEndian.PutUint16(payload[2:4], code)
	binary.BigEndian.PutUint64(payload[4:12], uint64(time.Now().UnixMilli()))
	copy(payload[12:28], idBytes)
	copy(payload[28:60], digestBytes)
	binary.BigEndian.PutUint64(payload[76:84], bytesValue)
	binary.BigEndian.PutUint32(payload[96:100], sequence)
	signed := append(append([]byte(nil), receiptDomain...), payload...)
	return append(payload, ed25519.Sign(signingKey, signed)...), nil
}

func writeTestWebSocketFrame(writer io.Writer, payload []byte) error {
	header := []byte{0x82}
	switch {
	case len(payload) <= 125:
		header = append(header, byte(len(payload)))
	case len(payload) <= 0xffff:
		header = append(header, 126, 0, 0)
		binary.BigEndian.PutUint16(header[len(header)-2:], uint16(len(payload)))
	default:
		header = append(header, 127, 0, 0, 0, 0, 0, 0, 0, 0)
		binary.BigEndian.PutUint64(header[len(header)-8:], uint64(len(payload)))
	}
	if _, err := writer.Write(header); err != nil {
		return err
	}
	_, err := writer.Write(payload)
	return err
}

func readTestWebSocketFrame(reader io.Reader) ([]byte, error) {
	message := make([]byte, 0)
	firstFragment := true
	for {
		var header [2]byte
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			return nil, err
		}
		opcode := header[0] & 0x0f
		if (firstFragment && opcode != 2) || (!firstFragment && opcode != 0) || header[1]&0x80 == 0 {
			return nil, fmt.Errorf("unexpected client WebSocket frame: %x", header)
		}
		length := uint64(header[1] & 0x7f)
		if length == 126 {
			var encoded [2]byte
			if _, err := io.ReadFull(reader, encoded[:]); err != nil {
				return nil, err
			}
			length = uint64(binary.BigEndian.Uint16(encoded[:]))
		} else if length == 127 {
			var encoded [8]byte
			if _, err := io.ReadFull(reader, encoded[:]); err != nil {
				return nil, err
			}
			length = binary.BigEndian.Uint64(encoded[:])
		}
		if length > maxFrameBytes || uint64(len(message))+length > maxFrameBytes {
			return nil, errors.New("client WebSocket frame is too large")
		}
		var mask [4]byte
		if _, err := io.ReadFull(reader, mask[:]); err != nil {
			return nil, err
		}
		payload := make([]byte, int(length))
		if _, err := io.ReadFull(reader, payload); err != nil {
			return nil, err
		}
		for index := range payload {
			payload[index] ^= mask[index%len(mask)]
		}
		message = append(message, payload...)
		if header[0]&0x80 != 0 {
			return message, nil
		}
		firstFragment = false
	}
}
