package transfer

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

type operation struct {
	Type      string            `json:"type"`
	Text      *string           `json:"text,omitempty"`
	Transfer  string            `json:"transfer,omitempty"`
	Entries   []manifestEntry   `json:"entries,omitempty"`
	Index     *int64            `json:"index,omitempty"`
	Offset    *int64            `json:"offset,omitempty"`
	Hashes    map[string]string `json:"hashes,omitempty"`
	Challenge string            `json:"challenge,omitempty"`
	Browse    *clientHello      `json:"browse,omitempty"`
	Job       string            `json:"job,omitempty"`
	Result    json.RawMessage   `json:"result,omitempty"`
}

type clientHello struct {
	Key          string   `json:"key"`
	Name         string   `json:"name"`
	Cwd          string   `json:"cwd"`
	Platform     string   `json:"platform"`
	Capabilities []string `json:"capabilities,omitempty"`
}

type incomingRecord struct {
	V         int       `json:"v"`
	ID        string    `json:"id"`
	Expires   int64     `json:"expires"`
	Token     string    `json:"token"`
	Operation operation `json:"operation"`
	Length    *int      `json:"length"`
}

func openRecord(private *ecdh.PrivateKey, frame []byte) (incomingRecord, []byte, error) {
	bad := errors.New("invalid record")
	if len(frame) < blockBytes+48 || len(frame) > maxFrameBytes || (len(frame)-48)%blockBytes != 0 {
		return incomingRecord{}, nil, bad
	}
	public, err := ecdh.X25519().NewPublicKey(frame[:32])
	if err != nil {
		return incomingRecord{}, nil, bad
	}
	dh, err := private.ECDH(public)
	if err != nil {
		return incomingRecord{}, nil, bad
	}
	defer clear(dh)
	key, nonce, err := recordKeys(dh, frame[:32], private.PublicKey().Bytes(), requestInfo)
	if err != nil {
		return incomingRecord{}, nil, err
	}
	defer clear(key)
	defer clear(nonce)
	block, err := aes.NewCipher(key)
	if err != nil {
		return incomingRecord{}, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return incomingRecord{}, nil, err
	}
	plain, err := aead.Open(nil, nonce, frame[32:], requestInfo)
	if err != nil {
		return incomingRecord{}, nil, bad
	}
	defer clear(plain)
	length := int(binary.BigEndian.Uint32(plain[:4]))
	if length < 2 || length > len(plain)-4 {
		return incomingRecord{}, nil, bad
	}
	var record incomingRecord
	if err := json.Unmarshal(plain[4:4+length], &record); err != nil || record.V != 1 || !idPattern.MatchString(record.ID) ||
		record.Expires < 0 || uint64(record.Expires) > maxSafeInteger || !tokenPattern.MatchString(record.Token) || record.Operation.Type == "" ||
		record.Length == nil || *record.Length < 0 || *record.Length > len(plain)-4-length {
		return incomingRecord{}, nil, bad
	}
	data := append([]byte(nil), plain[4+length:4+length+*record.Length]...)
	return record, data, nil
}

// recordKeys is RFC 9180 base-mode key scheduling for the fixed wire suite.
func recordKeys(dh, encapsulated, recipient, info []byte) (key, nonce []byte, err error) {
	kemSuite := []byte{'K', 'E', 'M', 0, 0x20}
	eae, err := labeledExtract(kemSuite, nil, "eae_prk", dh)
	if err != nil {
		return nil, nil, err
	}
	defer clear(eae)
	kemContext := append(append([]byte(nil), encapsulated...), recipient...)
	shared, err := labeledExpand(kemSuite, eae, "shared_secret", kemContext, 32)
	if err != nil {
		return nil, nil, err
	}
	defer clear(shared)
	suite := []byte{'H', 'P', 'K', 'E', 0, 0x20, 0, 1, 0, 2}
	pskHash, err := labeledExtract(suite, nil, "psk_id_hash", nil)
	if err != nil {
		return nil, nil, err
	}
	infoHash, err := labeledExtract(suite, nil, "info_hash", info)
	if err != nil {
		return nil, nil, err
	}
	context := append(append([]byte{0}, pskHash...), infoHash...)
	secret, err := labeledExtract(suite, shared, "secret", nil)
	if err != nil {
		return nil, nil, err
	}
	defer clear(secret)
	key, err = labeledExpand(suite, secret, "key", context, 32)
	if err != nil {
		return nil, nil, err
	}
	nonce, err = labeledExpand(suite, secret, "base_nonce", context, 12)
	if err != nil {
		clear(key)
		return nil, nil, err
	}
	return key, nonce, nil
}

func signReceipt(key ed25519.PrivateKey, value receipt) ([]byte, error) {
	payload := make([]byte, receiptPayloadLen, receiptBytes)
	if _, err := rand.Read(payload); err != nil {
		return nil, err
	}
	payload[0], payload[1] = 1, 0
	if value.Kind == "event" {
		payload[1] = 1
	}
	binary.BigEndian.PutUint16(payload[2:4], value.Code)
	binary.BigEndian.PutUint64(payload[4:12], uint64(value.At))
	if !idPattern.MatchString(value.ID) || !digestPattern.MatchString(value.Digest) || value.At < 0 || uint64(value.At) > maxSafeInteger || value.Bytes > maxSafeInteger || value.Offset > maxSafeInteger {
		return nil, errors.New("invalid receipt")
	}
	id, _ := hex.DecodeString(value.ID)
	d, _ := hex.DecodeString(value.Digest)
	transfer := value.Transfer
	if transfer == "" {
		transfer = strings.Repeat("0", 32)
	}
	if !idPattern.MatchString(transfer) {
		return nil, errors.New("invalid receipt")
	}
	t, _ := hex.DecodeString(transfer)
	copy(payload[12:28], id)
	copy(payload[28:60], d)
	copy(payload[60:76], t)
	binary.BigEndian.PutUint64(payload[76:84], value.Bytes)
	binary.BigEndian.PutUint32(payload[84:88], value.Index)
	binary.BigEndian.PutUint64(payload[88:96], value.Offset)
	binary.BigEndian.PutUint32(payload[96:100], value.Sequence)
	signed := append(append([]byte(nil), receiptDomain...), payload...)
	return append(payload, ed25519.Sign(key, signed)...), nil
}
