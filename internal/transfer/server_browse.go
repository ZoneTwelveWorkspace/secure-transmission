package transfer

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"slices"
	"time"
)

type serverBrowseState struct {
	hello    clientHello
	key      []byte
	sequence uint32
}

type transferProgress struct{ bytes, total uint64 }
type browseReply struct {
	value any
	err   error
}
type browseJob struct {
	connection   *serverConnection
	subscription string
	query        browseQuery
	reply        chan browseReply
	progress     chan transferProgress
	total        uint64
	lastActivity time.Time
}

func requireFields(data []byte, names ...string) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || fields == nil {
		return false
	}
	for _, name := range names {
		value, ok := fields[name]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	return true
}

func hasNullableFields(data []byte, names ...string) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil {
		return false
	}
	for _, name := range names {
		if _, ok := fields[name]; !ok {
			return false
		}
	}
	return true
}

func (entry *manifestEntry) UnmarshalJSON(data []byte) error {
	type plain manifestEntry
	var value plain
	if !requireFields(data, "path", "type", "size") || json.Unmarshal(data, &value) != nil {
		return errors.New("invalid manifest entry")
	}
	*entry = manifestEntry(value)
	return nil
}

func (entry *remoteEntry) UnmarshalJSON(data []byte) error {
	type plain remoteEntry
	var value plain
	if !requireFields(data, "name", "path", "type", "size", "modified", "mode", "directory") || json.Unmarshal(data, &value) != nil {
		return errors.New("invalid filesystem entry")
	}
	if len(value.Name) > 4096 || len(value.Path) > 16*1024 || value.Size < 0 || uint64(value.Size) > maxSafeInteger || math.IsInf(value.Modified, 0) || math.IsNaN(value.Modified) || !slices.Contains([]string{"directory", "file", "link", "other"}, value.Type) {
		return errors.New("invalid filesystem entry")
	}
	*entry = remoteEntry(value)
	return nil
}

func validateHello(hello *clientHello) error {
	if hello == nil || !tokenPattern.MatchString(hello.Key) || len(hello.Name) > 128 || len(hello.Cwd) > 16*1024 || len(hello.Platform) > 32 || len(hello.Capabilities) > 8 {
		return errors.New("invalid filesystem capability")
	}
	for _, capability := range hello.Capabilities {
		if capability != "preview" && capability != "download" {
			return errors.New("invalid filesystem capability")
		}
	}
	return nil
}

func decodeBrowseResult(data []byte) (any, error) {
	var envelope struct {
		Type string `json:"type"`
	}
	bad := errors.New("invalid filesystem response")
	if json.Unmarshal(data, &envelope) != nil {
		return nil, bad
	}
	switch envelope.Type {
	case "error":
		var value browseErrorResult
		if !requireFields(data, "message") || json.Unmarshal(data, &value) != nil || len(value.Message) > 4096 {
			return nil, bad
		}
		return value, nil
	case "stat":
		var value browseStatResult
		if !requireFields(data, "entry") || json.Unmarshal(data, &value) != nil {
			return nil, bad
		}
		return value, nil
	case "download":
		var value browseDownloadResult
		if !requireFields(data, "transfer", "bytes", "entries") || json.Unmarshal(data, &value) != nil || !idPattern.MatchString(value.Transfer) || value.Bytes < 0 || uint64(value.Bytes) > maxSafeInteger || value.Entries < 0 || value.Entries > 10_000 || value.SkippedLinks < 0 {
			return nil, bad
		}
		return value, nil
	case "preview":
		var value browsePreviewResult
		if !requireFields(data, "entry", "offset", "encoding", "content") || !hasNullableFields(data, "next") || json.Unmarshal(data, &value) != nil || value.Offset < 0 || value.Offset > value.Entry.Size || (value.Next != nil && (*value.Next <= value.Offset || *value.Next >= value.Entry.Size)) || (value.Encoding != "utf8" && value.Encoding != "hex") || len(value.Content) > previewBytes*4 {
			return nil, bad
		}
		return value, nil
	case "list":
		var value browseListResult
		if !requireFields(data, "path", "offset", "entries") || !hasNullableFields(data, "parent", "next") || json.Unmarshal(data, &value) != nil || len(value.Path) > 16*1024 || (value.Parent != nil && len(*value.Parent) > 16*1024) || value.Offset < 0 || uint64(value.Offset) > maxSafeInteger || (value.Next != nil && (*value.Next <= value.Offset || uint64(*value.Next) > maxSafeInteger)) || len(value.Entries) > pageSize {
			return nil, bad
		}
		return value, nil
	}
	return nil, bad
}

func resultType(value any) string {
	switch value.(type) {
	case browseErrorResult:
		return "error"
	case browseStatResult:
		return "stat"
	case browseListResult:
		return "list"
	case browsePreviewResult:
		return "preview"
	case browseDownloadResult:
		return "download"
	}
	return ""
}

func sealCommand(key []byte, signing ed25519.PrivateKey, subscription, binding string, command browseCommand) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("invalid control key")
	}
	aad, err := controlContext(subscription, binding)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(command)
	if err != nil {
		return nil, err
	}
	length := ((len(body) + 4 + blockBytes - 1) / blockBytes) * blockBytes
	if length+92 > maxFrameBytes {
		return nil, errors.New("control exceeds record limit")
	}
	plaintext := make([]byte, length)
	if _, err := rand.Read(plaintext); err != nil {
		return nil, err
	}
	defer clear(plaintext)
	binary.BigEndian.PutUint32(plaintext[:4], uint32(len(body)))
	copy(plaintext[4:], body)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	envelope := aead.Seal(nonce, nonce, plaintext, aad)
	signed := append(append([]byte(nil), aad...), envelope...)
	return append(envelope, ed25519.Sign(signing, signed)...), nil
}

func (s *server) dispatch(ctx context.Context, clientID string, query browseQuery, progress func(uint64, uint64)) (any, error) {
	if err := validateBrowseQuery(query); err != nil {
		return nil, err
	}
	jobID, err := newID()
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	var connection *serverConnection
	for candidate := range s.connections {
		if candidate.sub != nil && candidate.sub.id == clientID {
			connection = candidate
			break
		}
	}
	if connection == nil || s.stopped {
		s.mu.Unlock()
		return nil, errors.New("client is not connected")
	}
	sub := connection.sub
	if sub.browse == nil {
		s.mu.Unlock()
		return nil, errors.New("this client has not enabled filesystem browsing")
	}
	if (query.Type == "preview" || query.Type == "download") && !slices.Contains(sub.browse.hello.Capabilities, query.Type) {
		s.mu.Unlock()
		return nil, errors.New("update the client to enable previews and downloads")
	}
	for _, job := range s.jobs {
		if job.connection == connection {
			s.mu.Unlock()
			return nil, errors.New("a filesystem request is already in progress")
		}
	}
	if sub.browse.sequence == math.MaxUint32 {
		s.mu.Unlock()
		return nil, errors.New("reconnect the client to renew its control sequence")
	}
	sub.browse.sequence++
	frame, err := sealCommand(sub.browse.key, s.signing, sub.id, sub.digest, browseCommand{V: 1, ID: jobID, Sequence: sub.browse.sequence, Expires: time.Now().Add(30 * time.Second).UnixMilli(), Query: query})
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	job := &browseJob{connection: connection, subscription: sub.id, query: query, reply: make(chan browseReply, 1), progress: make(chan transferProgress, 64), lastActivity: time.Now()}
	s.jobs[jobID] = job
	if !connection.send(frame) {
		delete(s.jobs, jobID)
		s.mu.Unlock()
		return nil, errors.New("client connection is busy")
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.jobs[jobID] == job {
			delete(s.jobs, jobID)
		}
		s.mu.Unlock()
	}()
	timeout := 30 * time.Second
	if query.Type == "download" {
		timeout = 120 * time.Second
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case reply := <-job.reply:
			if download, ok := reply.value.(browseDownloadResult); ok && progress != nil {
				progress(uint64(download.Bytes), uint64(download.Bytes))
			}
			return reply.value, reply.err
		case update := <-job.progress:
			if progress != nil {
				progress(update.bytes, update.total)
			}
		case <-timer.C:
			s.mu.Lock()
			remaining := timeout - time.Since(job.lastActivity)
			s.mu.Unlock()
			if remaining > 0 {
				timer.Reset(remaining)
				continue
			}
			return nil, errors.New("filesystem request timed out")
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, errors.New("server stopped")
		}
	}
}

func (s *server) browse(ctx context.Context, clientID string, query browseQuery) (any, error) {
	if query.Type == "download" {
		return nil, errors.New("use the download API for transfers")
	}
	return s.dispatch(ctx, clientID, query, nil)
}

func (s *server) download(ctx context.Context, clientID, filename string, progress func(uint64, uint64)) (browseDownloadResult, error) {
	transfer, err := newID()
	if err != nil {
		return browseDownloadResult{}, err
	}
	value, err := s.dispatch(ctx, clientID, browseQuery{Type: "download", Path: filename, Transfer: transfer}, progress)
	if err != nil {
		return browseDownloadResult{}, err
	}
	if failure, ok := value.(browseErrorResult); ok {
		return browseDownloadResult{}, errors.New(failure.Message)
	}
	result, ok := value.(browseDownloadResult)
	if !ok {
		return browseDownloadResult{}, fmt.Errorf("client did not complete the download")
	}
	result.Destination = filepath.Join(s.storage.root, "received", result.Transfer, "files")
	return result, nil
}
