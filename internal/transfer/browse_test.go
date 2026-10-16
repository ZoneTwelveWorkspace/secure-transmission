package transfer

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenCommandIsCompatibleWithNodeServer(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("Node.js is not installed")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	controlKey := make([]byte, 32)
	if _, err := rand.Read(controlKey); err != nil {
		t.Fatal(err)
	}
	subscription := "00112233445566778899aabbccddeeff"
	bindingBytes := sha256.Sum256([]byte("subscription frame"))
	binding := hex.EncodeToString(bindingBytes[:])
	commandID := "ffeeddccbbaa99887766554433221100"
	expires := time.Now().Add(30 * time.Second).UnixMilli()
	input, err := json.Marshal(map[string]any{
		"key":          base64.RawURLEncoding.EncodeToString(controlKey),
		"signingKey":   base64.RawURLEncoding.EncodeToString(privateDER),
		"subscription": subscription, "digest": binding,
		"command": map[string]any{
			"v": 1, "id": commandID, "sequence": 1, "expires": expires,
			"query": map[string]any{"type": "list", "path": "/private/path", "offset": 7},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	script := `
import { sealCommand } from './src/browse-protocol.ts';
import { privateSigningKey } from './src/protocol.ts';
const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const input = JSON.parse(Buffer.concat(chunks));
const frame = sealCommand(Buffer.from(input.key, 'base64url'), privateSigningKey(input.signingKey), input.subscription, input.digest, input.command);
process.stdout.write(frame.toString('base64url'));
`
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	process := exec.Command("node", "--import", "tsx", "--input-type=module", "-e", script)
	process.Dir = root
	process.Stdin = bytes.NewReader(input)
	output, err := process.CombinedOutput()
	if err != nil {
		t.Fatalf("Node failed to seal a filesystem command: %v\n%s", err, output)
	}
	frame, err := base64.RawURLEncoding.DecodeString(string(output))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := openCommand(controlKey, publicKey, subscription, binding, frame)
	if err != nil {
		t.Fatal(err)
	}
	if opened.ID != commandID || opened.Sequence != 1 || opened.Expires != expires ||
		opened.Query.Type != "list" || opened.Query.Path != "/private/path" || opened.Query.Offset == nil || *opened.Query.Offset != 7 {
		t.Fatalf("unexpected filesystem command: %#v", opened)
	}
	frame[100] ^= 1
	if _, err := openCommand(controlKey, publicKey, subscription, binding, frame); err == nil {
		t.Fatal("tampered filesystem command was accepted")
	}
}
