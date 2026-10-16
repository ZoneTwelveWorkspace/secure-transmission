package transfer

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func legacyProject(t *testing.T) string {
	t.Helper()
	root := os.Getenv("LEGACY_PROJECT")
	if root == "" {
		t.Skip("set LEGACY_PROJECT to run Node.js interoperability checks")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("Node.js is not installed")
	}
	return root
}

func nodeProcess(t *testing.T, script string, input any) (*exec.Cmd, *json.Decoder, func()) {
	t.Helper()
	root := legacyProject(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	command := exec.CommandContext(ctx, "node", "--import", "tsx", "--input-type=module", "-e", script)
	command.Dir = root
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	command.Stdin = bytes.NewReader(encoded)
	var diagnostics bytes.Buffer
	command.Stderr = &diagnostics
	stdout, err := command.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	stop := func() {
		cancel()
		_ = command.Wait()
		if diagnostics.Len() > 0 && t.Failed() {
			t.Log(diagnostics.String())
		}
	}
	return command, json.NewDecoder(stdout), stop
}

func TestGoClientInteroperatesWithLegacyServer(t *testing.T) {
	legacyProject(t)
	state := filepath.Join(t.TempDir(), "state")
	p, err := initializeServer(state, "")
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "from-go.txt")
	contents := bytes.Repeat([]byte("Go to JavaScript\n"), 10_000)
	if err := os.WriteFile(source, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	script := `
import { startServer } from './src/server.ts';
let body = ''; for await (const part of process.stdin) body += part;
const input = JSON.parse(body);
const server = await startServer({ state: input.state, port: 0 });
process.stdout.write(JSON.stringify({ url: server.url }) + '\n');
try {
  const result = await new Promise((resolve, reject) => {
    const timer = setInterval(() => {
      const peer = server.clients().find(peer => peer.browsing);
      if (!peer) return;
      clearInterval(timer);
      server.download(peer.id, input.source).then(resolve, reject);
    }, 10);
  });
  process.stdout.write(JSON.stringify(result) + '\n');
} finally { await server.close(); }
`
	_, output, stop := nodeProcess(t, script, map[string]string{"state": state, "source": source})
	defer stop()
	var ready struct {
		URL string `json:"url"`
	}
	if err := output.Decode(&ready); err != nil {
		t.Fatal(err)
	}
	p.Endpoint = ready.URL
	client := fixtureClient(t, p, "http", nil)
	if _, err := sendMessage(client, "Go message"); err != nil {
		t.Fatal(err)
	}
	packed, err := packTransfer(p, []string{source}, filepath.Join(t.TempDir(), "spool"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deliverSpool(client, packed.directory); err != nil {
		t.Fatal(err)
	}
	live := fixtureClient(t, p, "ws", &filesystemBrowser{name: "Go", cwd: filepath.Dir(source)})
	if err := live.Connect(); err != nil {
		t.Fatal(err)
	}
	var download struct {
		Destination string `json:"destination"`
		Bytes       int64  `json:"bytes"`
	}
	if err := output.Decode(&download); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(download.Destination, filepath.Base(source)))
	if err != nil || !bytes.Equal(data, contents) || download.Bytes != int64(len(contents)) {
		t.Fatalf("legacy server could not download from Go: %v", err)
	}
	data, err = os.ReadFile(filepath.Join(state, "received", packed.transfer, "files", filepath.Base(source)))
	if err != nil || !bytes.Equal(data, contents) {
		t.Fatalf("legacy server could not receive Go upload: %v", err)
	}
}

func TestLegacyClientInteroperatesWithGoServer(t *testing.T) {
	legacyProject(t)
	f := newServerFixture(t)
	root := t.TempDir()
	source := filepath.Join(root, "from-node.txt")
	contents := bytes.Repeat([]byte("JavaScript to Go\n"), 10_000)
	if err := os.WriteFile(source, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	script := `
import { Transport } from './src/transport.ts';
import { FilesystemBrowser } from './src/filesystem.ts';
import { pack, deliverSpool, sendMessage } from './src/packing.ts';
let body = ''; for await (const part of process.stdin) body += part;
const input = JSON.parse(body);
const upload = new Transport(input.profile, { mode: 'http' });
await sendMessage(upload, 'Node message');
const packed = await pack(input.profile, [input.source], input.spool);
await deliverSpool(upload, packed.directory);
upload.close();
const client = new Transport(input.profile, { filesystem: new FilesystemBrowser('legacy', input.root) });
await client.connect();
process.stdout.write(JSON.stringify({ transfer: packed.transfer }) + '\n');
await new Promise(resolve => { process.once('SIGTERM', resolve); process.once('SIGINT', resolve); });
client.close();
`
	_, output, stop := nodeProcess(t, script, map[string]any{"profile": f.profile, "source": source, "root": root, "spool": filepath.Join(root, "spool")})
	defer stop()
	var ready struct {
		Transfer string `json:"transfer"`
	}
	if err := output.Decode(&ready); err != nil {
		t.Fatal(err)
	}
	peers := f.server.clients()
	if len(peers) != 1 || peers[0].Name != "legacy" {
		t.Fatalf("legacy client did not authenticate: %#v", peers)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	preview, err := f.server.browse(ctx, peers[0].ID, browseQuery{Type: "preview", Path: source})
	if err != nil || resultType(preview) != "preview" {
		t.Fatalf("legacy preview failed: %v", err)
	}
	download, err := f.server.download(ctx, peers[0].ID, source, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, filename := range []string{filepath.Join(download.Destination, "from-node.txt"), filepath.Join(f.state, "received", ready.Transfer, "files", "from-node.txt")} {
		file, err := os.Open(filename)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(file)
		_ = file.Close()
		if err != nil || !bytes.Equal(data, contents) {
			t.Fatalf("wrong legacy client transfer: %v", err)
		}
	}
}
