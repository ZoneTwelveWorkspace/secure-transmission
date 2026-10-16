package transfer

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestSealRecordIsCompatibleWithNodeHPKE(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("Node.js is not installed")
	}
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	record, err := newRecord("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", map[string]any{
		"type": "message", "text": "cross-language test",
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("payload")
	frame, err := sealRecord(privateKey.PublicKey(), record, payload)
	if err != nil {
		t.Fatal(err)
	}
	input, err := json.Marshal(map[string]string{
		"privateKey": base64.RawURLEncoding.EncodeToString(privateKey.Bytes()),
		"publicKey":  base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes()),
		"frame":      base64.RawURLEncoding.EncodeToString(frame),
	})
	if err != nil {
		t.Fatal(err)
	}
	script := `
import { CipherSuite, KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_256_GCM } from 'hpke';
const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const input = JSON.parse(Buffer.concat(chunks));
const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_256_GCM);
const privateKey = await suite.DeserializePrivateKey(Buffer.from(input.privateKey, 'base64url'));
const publicKey = await suite.DeserializePublicKey(Buffer.from(input.publicKey, 'base64url'));
const frame = Buffer.from(input.frame, 'base64url');
const info = Buffer.from('secure-transmitting/v1/request');
const plaintext = Buffer.from(await suite.Open({ privateKey, publicKey }, frame.subarray(0, 32), frame.subarray(32), { info, aad: info }));
const length = plaintext.readUInt32BE(0);
const header = JSON.parse(plaintext.subarray(4, 4 + length));
process.stdout.write(JSON.stringify({ header, data: plaintext.subarray(4 + length, 4 + length + header.length).toString('base64url') }));
`
	root := os.Getenv("LEGACY_PROJECT")
	if root == "" {
		t.Skip("set LEGACY_PROJECT to run Node.js interoperability checks")
	}
	command := exec.Command("node", "--input-type=module", "-e", script)
	command.Dir = root
	command.Stdin = bytes.NewReader(input)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("Node failed to open the Go HPKE frame: %v\n%s", err, output)
	}
	var opened struct {
		Header struct {
			V       int            `json:"v"`
			ID      string         `json:"id"`
			Expires int64          `json:"expires"`
			Token   string         `json:"token"`
			Length  int            `json:"length"`
			Op      map[string]any `json:"operation"`
		} `json:"header"`
		Data string `json:"data"`
	}
	if err := json.Unmarshal(output, &opened); err != nil {
		t.Fatalf("invalid Node result: %v\n%s", err, output)
	}
	if opened.Header.V != 1 || opened.Header.ID != record.ID || opened.Header.Expires != record.Expires ||
		opened.Header.Token != record.Token || opened.Header.Length != len(payload) || opened.Header.Op["type"] != "message" {
		t.Fatalf("opened record did not match: %#v", opened.Header)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(opened.Data)
	if err != nil || !bytes.Equal(decoded, payload) {
		t.Fatalf("opened payload did not match: %q (%v)", decoded, err)
	}
}

func TestReceiptVerification(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, receiptPayloadLen)
	payload[0] = 1
	payload[1] = 0
	binary.BigEndian.PutUint16(payload[2:4], codeComplete)
	binary.BigEndian.PutUint64(payload[4:12], uint64(time.Now().UnixMilli()))
	idBytes, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	copy(payload[12:28], idBytes)
	digestBytes := sha256.Sum256([]byte("request"))
	copy(payload[28:60], digestBytes[:])
	signed := append(append([]byte(nil), receiptDomain...), payload...)
	frame := append(append([]byte(nil), payload...), ed25519.Sign(privateKey, signed)...)
	value, err := parseReceipt(publicKey, frame)
	if err != nil {
		t.Fatal(err)
	}
	if value.Code != codeComplete || value.ID != "00112233445566778899aabbccddeeff" || value.Digest != hex.EncodeToString(digestBytes[:]) {
		t.Fatalf("unexpected receipt: %#v", value)
	}
	frame[100] ^= 1
	if _, err := parseReceipt(publicKey, frame); err == nil {
		t.Fatal("tampered receipt was accepted")
	}
}
