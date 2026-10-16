package transfer

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"regexp"
	"time"
)

const (
	blockBytes        = 4096
	chunkBytes        = 128 * 1024
	maxFrameBytes     = 2*1024*1024 + 48
	requestLifetime   = 24 * time.Hour
	receiptBytes      = 512
	receiptPayloadLen = receiptBytes - ed25519.SignatureSize
	maxSafeInteger    = uint64(1<<53 - 1)
)

const (
	codeOK        = 0
	codeComplete  = 1
	codeRejected  = 2
	codeNotFound  = 3
	codeBusy      = 4
	codeChallenge = 5
)

var (
	requestInfo   = []byte("secure-transmitting/v1/request")
	receiptDomain = []byte("secure-transmitting/v1/receipt")
	idPattern     = regexp.MustCompile(`^[a-f0-9]{32}$`)
	digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	tokenPattern  = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

type receipt struct {
	Kind     string
	Code     uint16
	ID       string
	Digest   string
	At       int64
	Transfer string
	Bytes    uint64
	Index    uint32
	Offset   uint64
	Sequence uint32
}

type requestRecord struct {
	V         int    `json:"v"`
	ID        string `json:"id"`
	Expires   int64  `json:"expires"`
	Token     string `json:"token"`
	Operation any    `json:"operation"`
}

type wireRecord struct {
	V         int    `json:"v"`
	ID        string `json:"id"`
	Expires   int64  `json:"expires"`
	Token     string `json:"token"`
	Operation any    `json:"operation"`
	Length    int    `json:"length"`
}

func newID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func newRecord(token string, operation any) (requestRecord, error) {
	id, err := newID()
	if err != nil {
		return requestRecord{}, err
	}
	return requestRecord{
		V: 1, ID: id, Expires: time.Now().Add(requestLifetime).UnixMilli(),
		Token: token, Operation: operation,
	}, nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// sealRecord implements the one fixed RFC 9180 suite used by the Node client:
// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and AES-256-GCM in base mode.
func sealRecord(recipient *ecdh.PublicKey, record requestRecord, data []byte) ([]byte, error) {
	header, err := json.Marshal(wireRecord{
		V: record.V, ID: record.ID, Expires: record.Expires, Token: record.Token,
		Operation: record.Operation, Length: len(data),
	})
	if err != nil {
		return nil, err
	}
	length := 4 + len(header) + len(data)
	padded := ((length + blockBytes - 1) / blockBytes) * blockBytes
	if padded+48 > maxFrameBytes {
		return nil, errors.New("record exceeds the supported size")
	}
	plaintext := make([]byte, padded)
	if _, err := rand.Read(plaintext); err != nil {
		return nil, err
	}
	defer clear(plaintext)
	binary.BigEndian.PutUint32(plaintext[:4], uint32(len(header)))
	copy(plaintext[4:], header)
	copy(plaintext[4+len(header):], data)

	enc, key, nonce, err := setupBaseSender(recipient, requestInfo)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	defer clear(nonce)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, requestInfo)
	frame := make([]byte, 0, len(enc)+len(ciphertext))
	frame = append(frame, enc...)
	frame = append(frame, ciphertext...)
	return frame, nil
}

func setupBaseSender(recipient *ecdh.PublicKey, info []byte) (enc, key, nonce []byte, err error) {
	curve := ecdh.X25519()
	ephemeral, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	sharedDH, err := ephemeral.ECDH(recipient)
	if err != nil {
		return nil, nil, nil, err
	}
	defer clear(sharedDH)
	enc = ephemeral.PublicKey().Bytes()
	kemContext := make([]byte, 0, len(enc)+len(recipient.Bytes()))
	kemContext = append(kemContext, enc...)
	kemContext = append(kemContext, recipient.Bytes()...)

	kemSuiteID := append([]byte("KEM"), 0x00, 0x20)
	eaePRK, err := labeledExtract(kemSuiteID, nil, "eae_prk", sharedDH)
	if err != nil {
		return nil, nil, nil, err
	}
	defer clear(eaePRK)
	sharedSecret, err := labeledExpand(kemSuiteID, eaePRK, "shared_secret", kemContext, 32)
	if err != nil {
		return nil, nil, nil, err
	}
	defer clear(sharedSecret)

	hpkeSuiteID := append([]byte("HPKE"), 0x00, 0x20, 0x00, 0x01, 0x00, 0x02)
	pskIDHash, err := labeledExtract(hpkeSuiteID, nil, "psk_id_hash", nil)
	if err != nil {
		return nil, nil, nil, err
	}
	defer clear(pskIDHash)
	infoHash, err := labeledExtract(hpkeSuiteID, nil, "info_hash", info)
	if err != nil {
		return nil, nil, nil, err
	}
	defer clear(infoHash)
	context := make([]byte, 1, 1+len(pskIDHash)+len(infoHash))
	context = append(context, pskIDHash...)
	context = append(context, infoHash...)
	secret, err := labeledExtract(hpkeSuiteID, sharedSecret, "secret", nil)
	if err != nil {
		return nil, nil, nil, err
	}
	defer clear(secret)
	key, err = labeledExpand(hpkeSuiteID, secret, "key", context, 32)
	if err != nil {
		return nil, nil, nil, err
	}
	nonce, err = labeledExpand(hpkeSuiteID, secret, "base_nonce", context, 12)
	if err != nil {
		clear(key)
		return nil, nil, nil, err
	}
	return enc, key, nonce, nil
}

func labeledExtract(suiteID, salt []byte, label string, ikm []byte) ([]byte, error) {
	labeledIKM := make([]byte, 0, len("HPKE-v1")+len(suiteID)+len(label)+len(ikm))
	labeledIKM = append(labeledIKM, "HPKE-v1"...)
	labeledIKM = append(labeledIKM, suiteID...)
	labeledIKM = append(labeledIKM, label...)
	labeledIKM = append(labeledIKM, ikm...)
	return hkdf.Extract[hash.Hash](func() hash.Hash { return sha256.New() }, labeledIKM, salt)
}

func labeledExpand(suiteID, prk []byte, label string, info []byte, length int) ([]byte, error) {
	labeledInfo := make([]byte, 2, 2+len("HPKE-v1")+len(suiteID)+len(label)+len(info))
	binary.BigEndian.PutUint16(labeledInfo, uint16(length))
	labeledInfo = append(labeledInfo, "HPKE-v1"...)
	labeledInfo = append(labeledInfo, suiteID...)
	labeledInfo = append(labeledInfo, label...)
	labeledInfo = append(labeledInfo, info...)
	return hkdf.Expand[hash.Hash](func() hash.Hash { return sha256.New() }, prk, string(labeledInfo), length)
}

func parseReceipt(publicKey ed25519.PublicKey, frame []byte) (receipt, error) {
	if len(frame) != receiptBytes {
		return receipt{}, errors.New("invalid server receipt")
	}
	payload := frame[:receiptPayloadLen]
	signed := make([]byte, 0, len(receiptDomain)+len(payload))
	signed = append(signed, receiptDomain...)
	signed = append(signed, payload...)
	if !ed25519.Verify(publicKey, signed, frame[receiptPayloadLen:]) {
		return receipt{}, errors.New("server signature verification failed")
	}
	if payload[0] != 1 || payload[1] > 1 {
		return receipt{}, errors.New("invalid server receipt")
	}
	at := binary.BigEndian.Uint64(payload[4:12])
	bytesValue := binary.BigEndian.Uint64(payload[76:84])
	offsetValue := binary.BigEndian.Uint64(payload[88:96])
	if at > maxSafeInteger || bytesValue > maxSafeInteger || offsetValue > maxSafeInteger {
		return receipt{}, errors.New("invalid server receipt")
	}
	return receipt{
		Kind: map[byte]string{0: "ack", 1: "event"}[payload[1]],
		Code: binary.BigEndian.Uint16(payload[2:4]), At: int64(at),
		ID: hex.EncodeToString(payload[12:28]), Digest: hex.EncodeToString(payload[28:60]),
		Transfer: hex.EncodeToString(payload[60:76]), Bytes: bytesValue,
		Index: binary.BigEndian.Uint32(payload[84:88]), Offset: offsetValue,
		Sequence: binary.BigEndian.Uint32(payload[96:100]),
	}, nil
}

func decodePublicEncryptionKey(encoded string) (*ecdh.PublicKey, error) {
	value, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(value) != 32 {
		return nil, errors.New("invalid client profile")
	}
	key, err := ecdh.X25519().NewPublicKey(value)
	if err != nil {
		return nil, fmt.Errorf("invalid encryption key: %w", err)
	}
	return key, nil
}

func decodePublicSigningKey(encoded string) (ed25519.PublicKey, error) {
	value, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errors.New("invalid client profile")
	}
	parsed, err := x509.ParsePKIXPublicKey(value)
	if err != nil {
		return nil, errors.New("invalid client profile")
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("signing key must be Ed25519")
	}
	return key, nil
}
