package transfer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type transferResult struct {
	Code     uint16
	Transfer string
	Bytes    uint64
	Index    uint32
	Offset   uint64
}

type transferState struct {
	V        int             `json:"v"`
	ID       string          `json:"id"`
	Owner    string          `json:"owner"`
	Entries  []manifestEntry `json:"entries"`
	Total    int64           `json:"total"`
	Received int64           `json:"received"`
	Index    int             `json:"index"`
	Offset   int64           `json:"offset"`
	Complete bool            `json:"complete"`
	Created  int64           `json:"created"`
	Job      string          `json:"job,omitempty"`
}

type storedReceipt struct {
	Digest  string `json:"digest"`
	Expires int64  `json:"expires"`
	Receipt string `json:"receipt"`
}

type storage struct {
	root     string
	maxBytes int64
	mu       sync.Mutex
}

func newStorage(root string, maxBytes int64) (*storage, error) {
	root, err := privateDirectory(root)
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"pending", "received", "messages", "requests"} {
		if _, err := privateDirectory(filepath.Join(root, name)); err != nil {
			return nil, err
		}
	}
	if maxBytes <= 0 || uint64(maxBytes) > maxSafeInteger {
		return nil, errors.New("invalid transfer size limit")
	}
	return &storage{root: root, maxBytes: maxBytes}, nil
}

func syncDirectory(directory string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	file, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func atomicJSON(filename string, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	id, err := newID()
	if err != nil {
		return err
	}
	temporary := filename + "." + id + ".partial"
	defer os.Remove(temporary)
	if err := writePrivate(temporary, encoded); err != nil {
		return err
	}
	if err := os.Rename(temporary, filename); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(filename))
}

func readJSON(filename string, target any) (bool, error) {
	data, err := readPrivate(filename, 16*1024*1024)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(data, target)
}

func (s *storage) cached(id string) (*storedReceipt, error) {
	if !idPattern.MatchString(id) {
		return nil, errors.New("invalid request")
	}
	var value storedReceipt
	found, err := readJSON(filepath.Join(s.root, "requests", id+".json"), &value)
	if !found || err != nil {
		return nil, err
	}
	return &value, nil
}

func (s *storage) cache(id string, value storedReceipt) error {
	if !idPattern.MatchString(id) {
		return errors.New("invalid request")
	}
	return atomicJSON(filepath.Join(s.root, "requests", id+".json"), value)
}

func (s *storage) cleanReceipts(now int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	directory := filepath.Join(s.root, "requests")
	items, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, item := range items {
		name := item.Name()
		if !strings.HasSuffix(name, ".json") || !idPattern.MatchString(strings.TrimSuffix(name, ".json")) {
			continue
		}
		var value storedReceipt
		found, err := readJSON(filepath.Join(directory, name), &value)
		if err != nil {
			return err
		}
		if found && value.Expires < now {
			if err := os.Remove(filepath.Join(directory, name)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *storage) load(transfer, owner string) (*transferState, string, error) {
	if !idPattern.MatchString(transfer) {
		return nil, "", errors.New("invalid transfer")
	}
	for _, folder := range []string{"received", "pending"} {
		directory := filepath.Join(s.root, folder, transfer)
		var state transferState
		found, err := readJSON(filepath.Join(directory, "metadata.json"), &state)
		if err != nil {
			return nil, "", err
		}
		if !found {
			continue
		}
		total, err := validateEntries(state.Entries)
		if err != nil || state.V != 1 || state.ID != transfer || state.Total != total || state.Received < 0 || state.Received > total || state.Index < 0 || state.Index > len(state.Entries) || state.Offset < 0 {
			return nil, "", errors.New("invalid transfer state")
		}
		if state.Owner != owner {
			return nil, "", errors.New("not authorized")
		}
		state.Complete = folder == "received"
		return &state, directory, nil
	}
	return nil, "", nil
}

func resultFor(state *transferState) transferResult {
	code := uint16(codeOK)
	if state.Complete {
		code = codeComplete
	}
	return transferResult{Code: code, Transfer: state.ID, Bytes: uint64(state.Received), Index: uint32(state.Index), Offset: uint64(state.Offset)}
}

func advance(state *transferState) {
	for state.Index < len(state.Entries) && (state.Entries[state.Index].Type != "file" || state.Entries[state.Index].Size == state.Offset) {
		state.Index++
		state.Offset = 0
	}
}

func rootMkdirAll(root *os.Root, directory string) error {
	if directory == "." {
		return nil
	}
	parts := strings.Split(directory, string(filepath.Separator))
	for i := range parts {
		name := filepath.Join(parts[:i+1]...)
		if err := root.Mkdir(name, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		info, err := root.Lstat(name)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("invalid transfer directory")
		}
	}
	return nil
}

func (s *storage) execute(request, owner string, op operation, data []byte) (transferResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	bad := func(message string) (transferResult, error) { return transferResult{}, errors.New(message) }
	if op.Type != "chunk" && len(data) != 0 {
		return bad("unexpected payload")
	}
	if op.Type == "subscribe" {
		return transferResult{}, nil
	}
	if op.Type == "message" {
		if op.Text == nil || len(*op.Text) > 256*1024 {
			return bad("invalid message")
		}
		filename := filepath.Join(s.root, "messages", request+".json")
		value := struct {
			Owner string `json:"owner"`
			Text  string `json:"text"`
		}{owner, *op.Text}
		var previous struct {
			Owner string `json:"owner"`
			Text  string `json:"text"`
		}
		found, err := readJSON(filename, &previous)
		if err != nil {
			return transferResult{}, err
		}
		if found {
			if previous != value {
				return bad("request collision")
			}
		} else {
			items, err := os.ReadDir(filepath.Dir(filename))
			if err != nil {
				return transferResult{}, err
			}
			if len(items) >= 10_000 {
				return bad("message quota reached")
			}
			if err := atomicJSON(filename, value); err != nil {
				return transferResult{}, err
			}
		}
		return transferResult{Code: codeComplete, Bytes: uint64(len(*op.Text))}, nil
	}
	if !idPattern.MatchString(op.Transfer) {
		return bad("invalid transfer")
	}
	state, directory, err := s.load(op.Transfer, owner)
	if err != nil {
		return transferResult{}, err
	}
	if op.Type == "begin" {
		total, err := validateEntries(op.Entries)
		if err != nil {
			return transferResult{}, err
		}
		if total > s.maxBytes {
			return bad("transfer exceeds the server size limit")
		}
		if op.Job != "" && !idPattern.MatchString(op.Job) {
			return bad("invalid download binding")
		}
		if state != nil {
			if state.Job != op.Job || !reflect.DeepEqual(state.Entries, op.Entries) {
				return bad("transfer collision")
			}
			return resultFor(state), nil
		}
		pending := filepath.Join(s.root, "pending")
		items, err := os.ReadDir(pending)
		if err != nil {
			return transferResult{}, err
		}
		if len(items) >= 64 {
			return bad("pending transfer quota reached")
		}
		directory = filepath.Join(pending, op.Transfer)
		if err := os.Mkdir(directory, 0o700); err != nil {
			if !errors.Is(err, os.ErrExist) {
				return transferResult{}, err
			}
			if _, err := privateDirectory(directory); err != nil {
				return transferResult{}, err
			}
			// Recover only this validated, unpublished transfer directory without metadata.
			if err := os.RemoveAll(directory); err != nil {
				return transferResult{}, err
			}
			if err := os.Mkdir(directory, 0o700); err != nil {
				return transferResult{}, err
			}
		}
		created := false
		defer func() {
			if !created {
				_ = os.RemoveAll(directory)
			}
		}()
		files := filepath.Join(directory, "files")
		if err := os.Mkdir(files, 0o700); err != nil {
			return transferResult{}, err
		}
		root, err := os.OpenRoot(files)
		if err != nil {
			return transferResult{}, err
		}
		defer root.Close()
		for _, entry := range op.Entries {
			name := filepath.FromSlash(entry.Path)
			dir := name
			if entry.Type == "file" {
				dir = filepath.Dir(name)
			}
			if err := rootMkdirAll(root, dir); err != nil {
				return transferResult{}, err
			}
			if entry.Type == "file" {
				f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
				if err != nil {
					return transferResult{}, err
				}
				if err := f.Sync(); err != nil {
					_ = f.Close()
					return transferResult{}, err
				}
				if err := f.Close(); err != nil {
					return transferResult{}, err
				}
			}
		}
		state = &transferState{V: 1, ID: op.Transfer, Owner: owner, Entries: op.Entries, Total: total, Created: time.Now().UnixMilli(), Job: op.Job}
		advance(state)
		if err := atomicJSON(filepath.Join(directory, "metadata.json"), state); err != nil {
			return transferResult{}, err
		}
		created = true
		return resultFor(state), nil
	}
	if state == nil {
		return transferResult{Code: codeNotFound, Transfer: op.Transfer}, nil
	}
	if op.Type == "status" {
		return resultFor(state), nil
	}
	if op.Job != state.Job {
		return bad("download binding mismatch")
	}
	root, err := os.OpenRoot(filepath.Join(directory, "files"))
	if err != nil {
		return transferResult{}, err
	}
	defer root.Close()
	if op.Type == "chunk" {
		if op.Index == nil || op.Offset == nil || *op.Index < 0 || *op.Index >= int64(len(state.Entries)) || *op.Offset < 0 || len(data) == 0 || len(data) > chunkBytes {
			return bad("invalid chunk")
		}
		entry := state.Entries[*op.Index]
		if entry.Type != "file" || *op.Offset > entry.Size || int64(len(data)) > entry.Size-*op.Offset {
			return bad("invalid chunk")
		}
		name := filepath.FromSlash(entry.Path)
		if state.Complete || *op.Index < int64(state.Index) || (*op.Index == int64(state.Index) && *op.Offset < state.Offset) {
			if !state.Complete && *op.Index == int64(state.Index) && *op.Offset+int64(len(data)) > state.Offset {
				return bad("overlapping retransmission")
			}
			file, err := root.Open(name)
			if err != nil {
				return transferResult{}, err
			}
			defer file.Close()
			previous := make([]byte, len(data))
			defer clear(previous)
			if n, err := file.ReadAt(previous, *op.Offset); err != nil || n != len(data) || !bytes.Equal(previous, data) {
				return bad("conflicting retransmission")
			}
			return resultFor(state), nil
		}
		if *op.Index != int64(state.Index) || *op.Offset != state.Offset {
			return bad("out-of-order chunk")
		}
		file, err := root.OpenFile(name, os.O_WRONLY, 0)
		if err != nil {
			return transferResult{}, err
		}
		n, writeErr := file.WriteAt(data, *op.Offset)
		if writeErr == nil && n != len(data) {
			writeErr = io.ErrShortWrite
		}
		if writeErr == nil {
			writeErr = file.Sync()
		}
		closeErr := file.Close()
		if writeErr != nil {
			return transferResult{}, writeErr
		}
		if closeErr != nil {
			return transferResult{}, closeErr
		}
		state.Offset += int64(len(data))
		state.Received += int64(len(data))
		advance(state)
		if err := atomicJSON(filepath.Join(directory, "metadata.json"), state); err != nil {
			return transferResult{}, err
		}
		return resultFor(state), nil
	}
	if op.Type != "commit" {
		return bad("unsupported operation")
	}
	if state.Index != len(state.Entries) || state.Received != state.Total || op.Hashes == nil {
		return bad("incomplete transfer")
	}
	files := 0
	buffer := make([]byte, chunkBytes)
	defer clear(buffer)
	for index, entry := range state.Entries {
		if entry.Type != "file" {
			continue
		}
		files++
		expected := op.Hashes[strconv.Itoa(index)]
		if !digestPattern.MatchString(expected) {
			return bad("invalid completion manifest")
		}
		file, err := root.Open(filepath.FromSlash(entry.Path))
		if err != nil {
			return transferResult{}, err
		}
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() != entry.Size {
			_ = file.Close()
			return bad("size mismatch")
		}
		hasher := sha256.New()
		n, err := io.CopyBuffer(hasher, file, buffer)
		_ = file.Close()
		if err != nil || n != entry.Size || hex.EncodeToString(hasher.Sum(nil)) != expected {
			return bad("file hash mismatch")
		}
	}
	if files != len(op.Hashes) {
		return bad("invalid completion manifest")
	}
	if !state.Complete {
		// Close directory handles before moving the tree, including on Windows.
		_ = root.Close()
		if err := os.Rename(directory, filepath.Join(s.root, "received", op.Transfer)); err != nil {
			return transferResult{}, fmt.Errorf("publish transfer: %w", err)
		}
		for _, folder := range []string{"received", "pending"} {
			if err := syncDirectory(filepath.Join(s.root, folder)); err != nil {
				return transferResult{}, err
			}
		}
		state.Complete = true
	}
	return resultFor(state), nil
}
