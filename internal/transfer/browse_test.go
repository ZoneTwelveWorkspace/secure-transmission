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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	root := os.Getenv("LEGACY_PROJECT")
	if root == "" {
		t.Skip("set LEGACY_PROJECT to run Node.js interoperability checks")
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

func TestPreviewPreservesUTF8PagesAndShowsBinaryAsHex(t *testing.T) {
	root := t.TempDir()
	text := strings.Repeat("a", previewBytes-1) + "資料\nlast page"
	filename := filepath.Join(root, "內容.txt")
	if err := os.WriteFile(filename, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	browser := &filesystemBrowser{cwd: root}
	first, ok := browser.query(browseQuery{Type: "preview", Path: filename}).(browsePreviewResult)
	if !ok || first.Encoding != "utf8" || first.Next == nil || *first.Next != previewBytes-1 {
		t.Fatalf("wrong first page: %#v", first)
	}
	second, ok := browser.query(browseQuery{Type: "preview", Path: filename, Offset: first.Next}).(browsePreviewResult)
	if !ok || second.Next != nil || first.Content+second.Content != text {
		t.Fatal("preview corrupted UTF-8 at page boundary")
	}
	binary := filepath.Join(root, "binary")
	if err := os.WriteFile(binary, []byte{0, 255, 128, 65}, 0o600); err != nil {
		t.Fatal(err)
	}
	preview, ok := browser.query(browseQuery{Type: "preview", Path: binary}).(browsePreviewResult)
	if !ok || preview.Encoding != "hex" || preview.Content != "00ff8041" {
		t.Fatalf("wrong binary preview: %#v", preview)
	}
	if _, ok := browser.query(browseQuery{Type: "preview", Path: root}).(browseErrorResult); !ok {
		t.Fatal("preview accepted a directory")
	}
}
