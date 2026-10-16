package transfer

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type serverFixture struct {
	server  *server
	profile profile
	state   string
}

func newServerFixture(t *testing.T) *serverFixture {
	t.Helper()
	state := filepath.Join(t.TempDir(), "state")
	p, err := initializeServer(state, "")
	if err != nil {
		t.Fatal(err)
	}
	s, err := startServer(serverOptions{state: state, port: 0})
	if err != nil {
		t.Fatal(err)
	}
	p.Endpoint = s.url
	f := &serverFixture{server: s, profile: p, state: state}
	t.Cleanup(func() {
		if err := f.server.close(); err != nil {
			t.Error(err)
		}
	})
	return f
}

func fixtureClient(t *testing.T, p profile, mode string, browser *filesystemBrowser) *Transport {
	t.Helper()
	client, err := newTransport(p, networkOptions{mode: mode, timeout: 2 * time.Second, attempts: 1, filesystem: browser})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

func TestServerMessageAndFileTransfersOverHTTPAndWebSocket(t *testing.T) {
	for _, mode := range []string{"http", "ws"} {
		t.Run(mode, func(t *testing.T) {
			f := newServerFixture(t)
			client := fixtureClient(t, f.profile, mode, nil)
			record, err := newRecord(f.profile.Token, map[string]any{"type": "message", "text": "hello encrypted world"})
			if err != nil {
				t.Fatal(err)
			}
			key, err := decodePublicEncryptionKey(f.profile.EncryptionKey)
			if err != nil {
				t.Fatal(err)
			}
			frame, err := sealRecord(key, record, nil)
			if err != nil {
				t.Fatal(err)
			}
			first, err := client.Send(frame, record.ID)
			if err != nil {
				t.Fatal(err)
			}
			second, err := client.Send(frame, record.ID)
			if err != nil || first != second || second.Code != codeComplete {
				t.Fatalf("idempotent retry failed: %v", err)
			}
			messages, err := os.ReadDir(filepath.Join(f.state, "messages"))
			if err != nil || len(messages) != 1 {
				t.Fatal("message was not saved exactly once")
			}
			source := filepath.Join(t.TempDir(), "tree")
			if err := os.MkdirAll(filepath.Join(source, "nested", "empty"), 0o700); err != nil {
				t.Fatal(err)
			}
			contents := bytes.Repeat([]byte{0, 1, 255}, chunkBytes)
			if err := os.WriteFile(filepath.Join(source, "nested", "資料.bin"), contents, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(source, "zero"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			packed, err := packTransfer(f.profile, []string{source}, filepath.Join(t.TempDir(), "spool"))
			if err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if _, err := deliverSpool(client, packed.directory); err != nil {
					t.Fatal(err)
				}
			}
			received, err := os.ReadFile(filepath.Join(f.state, "received", packed.transfer, "files", "tree", "nested", "資料.bin"))
			if err != nil || !bytes.Equal(received, contents) {
				t.Fatalf("wrong transferred data: %v", err)
			}
		})
	}
}

func TestPingAndUnauthenticatedRequestsExposeNoState(t *testing.T) {
	f := newServerFixture(t)
	base := strings.TrimSuffix(f.server.url, "/")
	for _, test := range []struct {
		method, path string
		status       int
	}{
		{"GET", "/550e8400-e29b-41d4-a716-446655440000/ping", 204},
		{"HEAD", "/ABCDEF0123456789ABCDEF0123456789/ping", 204},
		{"POST", "/550e8400-e29b-41d4-a716-446655440000/ping", 404},
		{"GET", "/550e8400-e29b-41d4-a716-446655440000/ping?x=1", 404},
		{"GET", "/550e8400-e29b-41d4-a716-446655440000/ping/", 404},
		{"GET", "/not-an-id/ping", 404},
		{"POST", "/", 404},
	} {
		req, _ := http.NewRequest(test.method, base+test.path, strings.NewReader("invalid"))
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if res.StatusCode != test.status || len(body) != 0 || res.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("%s %s returned %d, %q", test.method, test.path, res.StatusCode, body)
		}
	}
	wrong := f.profile
	wrong.Token = strings.Repeat("A", 43)
	if _, err := sendMessage(fixtureClient(t, wrong, "http", nil), "unauthorized"); err == nil {
		t.Fatal("accepted wrong credential")
	}
	items, _ := os.ReadDir(filepath.Join(f.state, "messages"))
	if len(items) != 0 {
		t.Fatal("unauthenticated requests created state")
	}
}

func TestRemoteListingPreviewAndDownload(t *testing.T) {
	f := newServerFixture(t)
	source := filepath.Join(t.TempDir(), "documents")
	if err := os.MkdirAll(filepath.Join(source, "empty"), 0o700); err != nil {
		t.Fatal(err)
	}
	text := strings.Repeat("a", previewBytes-1) + "資料"
	filename := filepath.Join(source, "內容.txt")
	if err := os.WriteFile(filename, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	skipped := 0
	if runtime.GOOS != "windows" {
		if err := os.Symlink("missing", filepath.Join(source, "broken")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(".", filepath.Join(source, "cycle")); err != nil {
			t.Fatal(err)
		}
		skipped = 2
	}
	client := fixtureClient(t, f.profile, "ws", &filesystemBrowser{name: "workstation", cwd: source})
	if err := client.Connect(); err != nil {
		t.Fatal(err)
	}
	peers := f.server.clients()
	if len(peers) != 1 || !peers[0].Preview || !peers[0].Download {
		t.Fatalf("wrong capabilities: %#v", peers)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	listing, err := f.server.browse(ctx, peers[0].ID, browseQuery{Type: "list", Path: source})
	if err != nil || resultType(listing) != "list" {
		t.Fatalf("list failed: %v %#v", err, listing)
	}
	preview, err := f.server.browse(ctx, peers[0].ID, browseQuery{Type: "preview", Path: filename})
	if err != nil || resultType(preview) != "preview" {
		t.Fatalf("preview failed: %v %#v", err, preview)
	}
	if preview.(browsePreviewResult).Next == nil || *preview.(browsePreviewResult).Next != previewBytes-1 {
		t.Fatal("UTF-8 preview split a character")
	}
	var progress []uint64
	download, err := f.server.download(ctx, peers[0].ID, source, func(n, total uint64) {
		progress = append(progress, n)
		if n > total {
			t.Error("invalid download progress")
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if download.SkippedLinks != skipped || download.Entries != 3 || download.Bytes != int64(len(text)) {
		t.Fatalf("wrong download result: %#v", download)
	}
	data, err := os.ReadFile(filepath.Join(download.Destination, "documents", "內容.txt"))
	if err != nil || string(data) != text {
		t.Fatalf("wrong download contents: %v", err)
	}
	if len(progress) == 0 || progress[len(progress)-1] != uint64(len(text)) {
		t.Fatal("missing completion progress")
	}
	if _, err := os.Stat(filename); err != nil {
		t.Fatal("source file disappeared")
	}
}

func TestInterruptedSpoolResumesAfterServerRestart(t *testing.T) {
	f := newServerFixture(t)
	filename := filepath.Join(t.TempDir(), "file")
	contents := bytes.Repeat([]byte("x"), chunkBytes+99)
	if err := os.WriteFile(filename, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	packed, err := packTransfer(f.profile, []string{filename}, filepath.Join(t.TempDir(), "outbox"))
	if err != nil {
		t.Fatal(err)
	}
	spool, _, err := loadSpool(packed.directory, f.profile)
	if err != nil {
		t.Fatal(err)
	}
	client := fixtureClient(t, f.profile, "http", nil)
	for _, item := range spool.Frames[:2] {
		frame, _ := os.ReadFile(filepath.Join(packed.directory, item.File))
		if _, err := client.Send(frame, item.ID); err != nil {
			t.Fatal(err)
		}
	}
	address := f.server.listener.Addr().(*net.TCPAddr)
	if err := f.server.close(); err != nil {
		t.Fatal(err)
	}
	f.server, err = startServer(serverOptions{state: f.state, port: address.Port})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deliverSpool(fixtureClient(t, f.profile, "ws", nil), packed.directory); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(f.state, "received", packed.transfer, "files", "file"))
	if err != nil || !bytes.Equal(data, contents) {
		t.Fatalf("resume failed: %v", err)
	}
}

func TestDownloadRecordsRequireTheSelectedConnection(t *testing.T) {
	f := newServerFixture(t)
	clientID, jobID, transfer := strings.Repeat("a", 32), strings.Repeat("b", 32), strings.Repeat("c", 32)
	selected := &serverConnection{sub: &serverSubscription{id: clientID}}
	other := &serverConnection{sub: &serverSubscription{id: strings.Repeat("d", 32)}}
	f.server.mu.Lock()
	f.server.jobs[jobID] = &browseJob{connection: selected, subscription: clientID, query: browseQuery{Type: "download", Transfer: transfer}, progress: make(chan transferProgress, 1)}
	f.server.mu.Unlock()
	key, _ := decodePublicEncryptionKey(f.profile.EncryptionKey)
	send := func(connection *serverConnection, op any) receipt {
		t.Helper()
		record, _ := newRecord(f.profile.Token, op)
		frame, err := sealRecord(key, record, nil)
		if err != nil {
			t.Fatal(err)
		}
		reply, err := f.server.handle(frame, connection)
		if err != nil {
			t.Fatal(err)
		}
		signing, _ := decodePublicSigningKey(f.profile.SigningKey)
		value, err := parseReceipt(signing, reply)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	begin := map[string]any{"type": "begin", "transfer": transfer, "job": jobID, "entries": []manifestEntry{{Path: "empty", Type: "file", Size: 0}}}
	if send(other, begin).Code != codeRejected {
		t.Fatal("another connection supplied a requested download")
	}
	if send(selected, begin).Code != codeOK {
		t.Fatal("selected connection could not begin its download")
	}
	f.server.mu.Lock()
	delete(f.server.jobs, jobID)
	f.server.mu.Unlock()
	commit := map[string]any{"type": "commit", "transfer": transfer, "hashes": map[string]string{"0": digest(nil)}}
	if send(other, commit).Code != codeRejected {
		t.Fatal("download lost its binding after disconnect")
	}
	if published, _ := os.ReadDir(filepath.Join(f.state, "received")); len(published) != 0 {
		data, _ := json.Marshal(published)
		t.Fatalf("published an unbound download: %s", data)
	}
}
