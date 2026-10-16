package transfer

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestGeneratedClientRunsIndependently(t *testing.T) {
	if testing.Short() {
		t.Skip("standalone client compilation")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("Go compiler is unavailable")
	}
	f := newServerFixture(t)
	root := t.TempDir()
	filename := filepath.Join(root, "selected.txt")
	if err := os.WriteFile(filename, []byte("standalone download"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "client")
	if runtime.GOOS == "windows" {
		output += ".exe"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := generateClient(ctx, f.profile, generateOptions{output: output}); err != nil {
		t.Fatal(err)
	}
	if err := generateClient(ctx, f.profile, generateOptions{output: output}); err == nil {
		t.Fatal("generation overwrote an existing binary")
	}
	for _, args := range [][]string{{"help"}, {"message", "standalone message"}, {"not-a-command"}} {
		command := exec.CommandContext(ctx, output, args...)
		command.Dir = root
		var stdout, stderr bytes.Buffer
		command.Stdout = &stdout
		command.Stderr = &stderr
		err := command.Run()
		if (args[0] == "not-a-command") != (err != nil) {
			t.Fatalf("wrong command exit: %q %v", args, err)
		}
		if stdout.String() != "hit\n" || stderr.Len() != 0 {
			t.Fatalf("unexpected generated output: %q / %q", stdout.String(), stderr.String())
		}
	}
	watchCtx, stop := context.WithCancel(ctx)
	watch := exec.CommandContext(watchCtx, output, "watch", "--name", "standalone")
	watch.Dir = root
	var stdout, stderr bytes.Buffer
	watch.Stdout = &stdout
	watch.Stderr = &stderr
	if err := watch.Start(); err != nil {
		stop()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- watch.Wait() }()
	defer func() {
		stop()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("generated client did not exit")
		}
		if stdout.String() != "hit\n" || stderr.Len() != 0 {
			t.Errorf("unexpected watch output: %q / %q", stdout.String(), stderr.String())
		}
	}()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	var clientID string
	for clientID == "" {
		select {
		case <-ticker.C:
			for _, peer := range f.server.clients() {
				if peer.Name == "standalone" {
					clientID = peer.ID
					break
				}
			}
		case <-deadline.C:
			t.Fatal("generated client did not authenticate")
		case err := <-done:
			t.Fatalf("generated client exited before connecting: %v", err)
		}
	}
	result, err := f.server.download(ctx, clientID, filename, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(result.Destination, "selected.txt"))
	if err != nil || string(data) != "standalone download" {
		t.Fatalf("standalone client download failed: %v", err)
	}
}

func TestTransportNetworkPolicyAndDefaultReconnectDelay(t *testing.T) {
	_, p := testEncryptionProfile(t)
	// A complete profile is supplied by initialization; no endpoint key discovery occurs.
	state := filepath.Join(t.TempDir(), "state")
	p, err := initializeServer(state, "https://example.test/")
	if err != nil {
		t.Fatal(err)
	}
	client, err := newTransport(p, networkOptions{mode: "ws", timeout: time.Second, attempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	if client.options.reconnectDelay != 5*time.Minute {
		t.Fatal("wrong default reconnect interval")
	}
	client.Close()
	for _, endpoint := range []string{"http://example.test/", "ws://example.test/", "http://service.onion/"} {
		p.Endpoint = endpoint
		if client, err := newTransport(p, networkOptions{mode: "ws", timeout: time.Second, attempts: 1}); err == nil {
			client.Close()
			t.Fatalf("accepted endpoint without required options: %s", endpoint)
		}
	}
	for _, endpoint := range []string{"https://user:pass@example.test/", "https://example.test/?token=x", "https://example.test/#fragment"} {
		if _, err := validatedEndpoint(endpoint); err == nil {
			t.Fatal("accepted credentials or metadata in URL")
		}
	}
	if _, err := networkDialer("socks5://127.0.0.1:9050", time.Second); err == nil {
		t.Fatal("accepted a proxy scheme without proxy DNS")
	}
	if strings.Contains(serverHelp, "Node.js") {
		t.Fatal("Go CLI still depends on Node.js")
	}
}
