package transfer

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestServerIdentityAndReceiverProtocol(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	p, err := initializeServer(state, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := initializeServer(state, ""); err == nil {
		t.Fatal("initialization overwrote identity")
	}
	keys, private, signing, err := loadServerKeys(state)
	if err != nil {
		t.Fatal(err)
	}
	if keys.TokenHash != digest([]byte(p.Token)) {
		t.Fatal("wrong capability hash")
	}
	record, err := newRecord(p.Token, map[string]any{"type": "message", "text": "hello"})
	if err != nil {
		t.Fatal(err)
	}
	frame, err := sealRecord(private.PublicKey(), record, nil)
	if err != nil {
		t.Fatal(err)
	}
	opened, data, err := openRecord(private, frame)
	if err != nil || opened.Operation.Text == nil || *opened.Operation.Text != "hello" || len(data) != 0 {
		t.Fatalf("cannot receive record: %v", err)
	}
	frame[100] ^= 1
	if _, _, err := openRecord(private, frame); err == nil {
		t.Fatal("accepted tampered ciphertext")
	}
	signed, err := signReceipt(signing, receipt{Kind: "ack", ID: record.ID, Digest: digest(frame), Code: codeComplete})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseReceipt(signing.Public().(ed25519.PublicKey), signed); err != nil {
		t.Fatal(err)
	}
}

func TestStorageResumesAndVerifiesBeforePublication(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	store, err := newStorage(state, 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	private, p := testEncryptionProfile(t)
	source := filepath.Join(t.TempDir(), "tree")
	if err := os.MkdirAll(filepath.Join(source, "empty"), 0o700); err != nil {
		t.Fatal(err)
	}
	contents := make([]byte, chunkBytes+17)
	if _, err := rand.Read(contents); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "file.bin"), contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "zero"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var result transferResult
	count := 0
	_, _, err = streamEncryptedTransfer(p, []string{source}, "", func(item transferFrame) error {
		record, data, err := openRecord(private, item.frame)
		if err != nil {
			return err
		}
		defer clear(data)
		result, err = store.execute(record.ID, "owner", record.Operation, data)
		if err != nil {
			return err
		}
		if item.phase == "chunk" {
			// Reopen durable state between chunks and retry the exact data.
			store, err = newStorage(state, 1024*1024)
			if err != nil {
				return err
			}
			if _, err := store.execute(record.ID, "owner", record.Operation, data); err != nil {
				return err
			}
		}
		if item.phase != "commit" {
			published, err := os.ReadDir(filepath.Join(state, "received"))
			if err != nil {
				return err
			}
			if len(published) != 0 {
				t.Fatal("published an incomplete tree")
			}
		}
		count++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Code != codeComplete || result.Bytes != uint64(len(contents)) || count != 4 {
		t.Fatalf("wrong completion: %#v", result)
	}
	received, err := os.ReadFile(filepath.Join(state, "received", result.Transfer, "files", "tree", "file.bin"))
	if err != nil || !bytes.Equal(received, contents) {
		t.Fatalf("wrong received bytes: %v", err)
	}
}

func TestStorageRejectsUnsafePathsWrongHashesAndOutOfOrderChunks(t *testing.T) {
	for _, path := range []string{"../escape", "/absolute", "a/../../b", "a\\b", "a//b"} {
		if _, err := validateEntries([]manifestEntry{{Path: path, Type: "file", Size: 0}}); err == nil {
			t.Fatalf("accepted unsafe path %q", path)
		}
	}
	store, err := newStorage(filepath.Join(t.TempDir(), "state"), 10)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 32)
	begin := operation{Type: "begin", Transfer: id, Entries: []manifestEntry{{Path: "file", Type: "file", Size: 3}}}
	if _, err := store.execute(id, "owner", begin, nil); err != nil {
		t.Fatal(err)
	}
	index, offset := int64(0), int64(1)
	op := operation{Type: "chunk", Transfer: id, Index: &index, Offset: &offset}
	if _, err := store.execute(id, "owner", op, []byte("b")); err == nil {
		t.Fatal("accepted an out-of-order chunk")
	}
	offset = 0
	if _, err := store.execute(id, "owner", op, []byte("abc")); err != nil {
		t.Fatal(err)
	}
	commit := operation{Type: "commit", Transfer: id, Hashes: map[string]string{"0": strings.Repeat("0", 64)}}
	if _, err := store.execute(id, "owner", commit, nil); err == nil {
		t.Fatal("published with wrong hash")
	}
	commit.Hashes["0"] = digest([]byte("abc"))
	if _, err := store.execute(id, "another owner", commit, nil); err == nil {
		t.Fatal("accepted another owner's transfer")
	}
	result, err := store.execute(id, "owner", commit, nil)
	if err != nil || result.Code != codeComplete {
		t.Fatalf("cannot publish valid transfer: %v", err)
	}
	// metadata stays compatible with the original state layout.
	data, err := os.ReadFile(filepath.Join(store.root, "received", id, "metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if json.Unmarshal(data, &value) != nil || value["owner"] != "owner" {
		t.Fatal("invalid metadata")
	}
}
