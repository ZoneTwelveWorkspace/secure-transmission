package transfer

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPackTransferProducesResumableProtocolFrames(t *testing.T) {
	privateKey, p := testEncryptionProfile(t)
	root := t.TempDir()
	source := filepath.Join(root, "documents")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	contents := bytes.Repeat([]byte("x"), chunkBytes+17)
	if err := os.WriteFile(filepath.Join(source, "report.bin"), contents, 0o600); err != nil {
		t.Fatal(err)
	}
	spoolDirectory := filepath.Join(root, "spool")
	packed, err := packTransfer(p, []string{source}, spoolDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if packed.temporary || packed.bytes != int64(len(contents)) || packed.frames != 4 {
		t.Fatalf("unexpected packed transfer: %#v", packed)
	}
	state, resolved, err := loadSpool(spoolDirectory, p)
	if err != nil {
		t.Fatal(err)
	}
	if state.Transfer != packed.transfer || len(state.Frames) != 4 {
		t.Fatalf("unexpected spool: %#v", state)
	}
	var openedContents []byte
	for index, item := range state.Frames {
		frame, err := os.ReadFile(filepath.Join(resolved, item.File))
		if err != nil {
			t.Fatal(err)
		}
		record, data, err := openTestRecord(privateKey, frame)
		if err != nil {
			t.Fatal(err)
		}
		operation, ok := record.Operation.(map[string]any)
		if !ok || operation["transfer"] != packed.transfer {
			t.Fatalf("invalid operation in frame %d: %#v", index, record.Operation)
		}
		switch index {
		case 0:
			if operation["type"] != "begin" || len(data) != 0 {
				t.Fatalf("invalid begin frame: %#v", operation)
			}
		case 1, 2:
			if operation["type"] != "chunk" || len(data) == 0 {
				t.Fatalf("invalid chunk frame: %#v", operation)
			}
			openedContents = append(openedContents, data...)
		case 3:
			if operation["type"] != "commit" || len(data) != 0 {
				t.Fatalf("invalid commit frame: %#v", operation)
			}
		}
	}
	if !bytes.Equal(openedContents, contents) {
		t.Fatal("packed chunks did not reconstruct the source file")
	}
}

func TestTransferRejectsAFileChangedAfterManifest(t *testing.T) {
	_, p := testEncryptionProfile(t)
	filename := filepath.Join(t.TempDir(), "source.txt")
	if err := os.WriteFile(filename, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := streamEncryptedTransfer(p, []string{filename}, "", func(item transferFrame) error {
		if item.phase == "begin" {
			return os.WriteFile(filename, []byte("changed and longer"), 0o600)
		}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "source file changed") {
		t.Fatalf("expected source-change rejection, got %v", err)
	}
}

func TestTransferRejectsSymbolicLinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks may require elevated Windows privileges")
	}
	_, p := testEncryptionProfile(t)
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	_, _, err := streamEncryptedTransfer(p, []string{link}, "", func(transferFrame) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "symbolic links") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
}

func testEncryptionProfile(t *testing.T) (*ecdh.PrivateKey, profile) {
	t.Helper()
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		t.Fatal(err)
	}
	return privateKey, profile{
		V: 1, EncryptionKey: base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes()),
		Token: base64.RawURLEncoding.EncodeToString(token), Endpoint: "http://127.0.0.1:8080/",
	}
}

func TestDownloadStreamSkipsNestedLinksAndBindsEveryRecord(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require Windows privileges")
	}
	private, p := testEncryptionProfile(t)
	root := t.TempDir()
	source := filepath.Join(root, "folder")
	if err := os.MkdirAll(filepath.Join(source, "empty"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "file"), []byte("included"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing", filepath.Join(source, "broken")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(".", filepath.Join(source, "cycle")); err != nil {
		t.Fatal(err)
	}
	job := strings.Repeat("a", 32)
	_, _, err := streamTransfer(p, []string{source}, "", job, true, func(item transferFrame) error {
		if item.entries != 3 || item.skippedLinks != 2 {
			t.Fatalf("wrong manifest counts: %#v", item)
		}
		record, _, err := openTestRecord(private, item.frame)
		if err != nil {
			return err
		}
		if record.Operation.(map[string]any)["job"] != job {
			t.Fatal("download record lost connection binding")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
