package transfer

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatchReconnectsWithFreshAuthenticationAfterServerRestart(t *testing.T) {
	f := newServerFixture(t)
	root := t.TempDir()
	filename := filepath.Join(root, "after-restart.txt")
	if err := os.WriteFile(filename, []byte("reconnected"), 0o600); err != nil {
		t.Fatal(err)
	}
	connected := make(chan struct{}, 4)
	client, err := newTransport(f.profile, networkOptions{mode: "ws", timeout: time.Second, attempts: 1, reconnectDelay: 20 * time.Millisecond, filesystem: &filesystemBrowser{name: "returning", cwd: root}, onConnect: func() { connected <- struct{}{} }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Watch(ctx) }()
	defer func() {
		cancel()
		client.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("watch did not stop")
		}
	}()
	wait := func() {
		t.Helper()
		select {
		case <-connected:
		case err := <-done:
			t.Fatalf("watch exited: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("watch did not connect")
		}
	}
	wait()
	previous := f.server.clients()[0].ID
	port := f.server.listener.Addr().(*net.TCPAddr).Port
	if err := f.server.close(); err != nil {
		t.Fatal(err)
	}
	f.server, err = startServer(serverOptions{state: f.state, port: port})
	if err != nil {
		t.Fatal(err)
	}
	wait()
	peers := f.server.clients()
	if len(peers) != 1 || peers[0].ID == previous {
		t.Fatal("reconnection reused an old subscription")
	}
	requestCtx, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	result, err := f.server.download(requestCtx, peers[0].ID, filename, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(result.Destination, "after-restart.txt"))
	if err != nil || string(data) != "reconnected" {
		t.Fatalf("browsing failed after reconnect: %v", err)
	}
}

func TestCancelInterruptsTheFiveMinuteReconnectWait(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	p, err := initializeServer(state, "")
	if err != nil {
		t.Fatal(err)
	}
	client, err := newTransport(p, networkOptions{mode: "ws", timeout: time.Second, attempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	attempted := make(chan struct{}, 1)
	client.dial = func(context.Context, string, string) (net.Conn, error) {
		attempted <- struct{}{}
		return nil, errors.New("offline")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- client.Watch(ctx) }()
	select {
	case <-attempted:
	case <-time.After(time.Second):
		t.Fatal("first attempt was not immediate")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation waited for reconnect delay")
	}
}
