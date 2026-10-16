package transfer

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const pageSize = 200
const previewBytes = 64 * 1024

var controlDomain = []byte("secure-transmitting/v1/filesystem-control")

type browseQuery struct {
	Type     string `json:"type"`
	Path     string `json:"path"`
	Offset   *int64 `json:"offset,omitempty"`
	Transfer string `json:"transfer,omitempty"`
}

type browseCommand struct {
	V        int         `json:"v"`
	ID       string      `json:"id"`
	Sequence uint32      `json:"sequence"`
	Expires  int64       `json:"expires"`
	Query    browseQuery `json:"query"`
}

type remoteEntry struct {
	Name      string  `json:"name"`
	Path      string  `json:"path"`
	Type      string  `json:"type"`
	Size      int64   `json:"size"`
	Modified  float64 `json:"modified"`
	Mode      uint32  `json:"mode"`
	Directory bool    `json:"directory"`
}

type browseListResult struct {
	Type    string        `json:"type"`
	Path    string        `json:"path"`
	Parent  *string       `json:"parent"`
	Offset  int64         `json:"offset"`
	Next    *int64        `json:"next"`
	Entries []remoteEntry `json:"entries"`
}

type browseStatResult struct {
	Type  string      `json:"type"`
	Entry remoteEntry `json:"entry"`
}

type browseErrorResult struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

type browsePreviewResult struct {
	Type     string      `json:"type"`
	Entry    remoteEntry `json:"entry"`
	Offset   int64       `json:"offset"`
	Next     *int64      `json:"next"`
	Encoding string      `json:"encoding"`
	Content  string      `json:"content"`
}

type browseDownloadResult struct {
	Type         string `json:"type"`
	Transfer     string `json:"transfer"`
	Bytes        int64  `json:"bytes"`
	Entries      int    `json:"entries"`
	SkippedLinks int    `json:"skippedLinks"`
	Destination  string `json:"-"`
}

type filesystemBrowser struct {
	name string
	cwd  string
}

func newFilesystemBrowser(name string) (*filesystemBrowser, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	cwd, err = filepath.Abs(cwd)
	if err != nil {
		return nil, err
	}
	return &filesystemBrowser{name: name, cwd: cwd}, nil
}

func validateBrowseQuery(query browseQuery) error {
	if query.Type != "list" && query.Type != "stat" && query.Type != "preview" && query.Type != "download" {
		return errors.New("invalid browse request")
	}
	if query.Path == "" || strings.ContainsRune(query.Path, 0) || len([]byte(query.Path)) > 16*1024 {
		return errors.New("invalid browse request")
	}
	if query.Offset != nil && (*query.Offset < 0 || uint64(*query.Offset) > maxSafeInteger || (query.Type == "list" && *query.Offset > 1_000_000)) {
		return errors.New("invalid browse request")
	}
	if query.Type == "download" && !idPattern.MatchString(query.Transfer) {
		return errors.New("invalid download request")
	}
	return nil
}

func controlContext(subscription, frameDigest string) ([]byte, error) {
	if !idPattern.MatchString(subscription) || !digestPattern.MatchString(frameDigest) {
		return nil, errors.New("invalid control context")
	}
	subscriptionBytes, _ := hex.DecodeString(subscription)
	digestBytes, _ := hex.DecodeString(frameDigest)
	result := make([]byte, 0, len(controlDomain)+len(subscriptionBytes)+len(digestBytes))
	result = append(result, controlDomain...)
	result = append(result, subscriptionBytes...)
	result = append(result, digestBytes...)
	return result, nil
}

func openCommand(key []byte, signingKey ed25519.PublicKey, subscription, frameDigest string, frame []byte) (browseCommand, error) {
	if len(key) != 32 || len(frame) < blockBytes+92 || len(frame) > maxFrameBytes || (len(frame)-92)%blockBytes != 0 {
		return browseCommand{}, errors.New("invalid filesystem control")
	}
	aad, err := controlContext(subscription, frameDigest)
	if err != nil {
		return browseCommand{}, err
	}
	envelope := frame[:len(frame)-ed25519.SignatureSize]
	signed := make([]byte, 0, len(aad)+len(envelope))
	signed = append(signed, aad...)
	signed = append(signed, envelope...)
	if !ed25519.Verify(signingKey, signed, frame[len(envelope):]) {
		return browseCommand{}, errors.New("server control signature verification failed")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return browseCommand{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return browseCommand{}, err
	}
	if len(envelope) < aead.NonceSize()+aead.Overhead() {
		return browseCommand{}, errors.New("invalid filesystem control")
	}
	plaintext, err := aead.Open(nil, envelope[:12], envelope[12:], aad)
	if err != nil {
		return browseCommand{}, errors.New("invalid filesystem control")
	}
	defer clear(plaintext)
	if len(plaintext) < 4 {
		return browseCommand{}, errors.New("invalid filesystem control")
	}
	length := int(binary.BigEndian.Uint32(plaintext[:4]))
	if length < 1 || length > len(plaintext)-4 {
		return browseCommand{}, errors.New("invalid filesystem control")
	}
	var command browseCommand
	if err := json.Unmarshal(plaintext[4:4+length], &command); err != nil || command.V != 1 ||
		!idPattern.MatchString(command.ID) || command.Expires < time.Now().Add(-30*time.Second).UnixMilli() ||
		command.Expires > time.Now().Add(time.Minute).UnixMilli() {
		return browseCommand{}, errors.New("expired or invalid filesystem control")
	}
	if err := validateBrowseQuery(command.Query); err != nil {
		return browseCommand{}, err
	}
	return command, nil
}

func (b *filesystemBrowser) resolve(path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Clean(filepath.Join(b.cwd, path))
}

func (b *filesystemBrowser) entry(filename string) (remoteEntry, error) {
	info, err := os.Lstat(filename)
	if err != nil {
		return remoteEntry{}, err
	}
	directory := info.IsDir()
	entryType := "other"
	if info.Mode()&os.ModeSymlink != 0 {
		entryType = "link"
		if target, statErr := os.Stat(filename); statErr == nil {
			directory = target.IsDir()
		}
	} else if info.IsDir() {
		entryType = "directory"
	} else if info.Mode().IsRegular() {
		entryType = "file"
	}
	name := filepath.Base(filename)
	if name == "." || name == string(filepath.Separator) {
		name = filename
	}
	size := info.Size()
	if size < 0 {
		size = 0
	}
	return remoteEntry{
		Name: name, Path: filename, Type: entryType, Size: size,
		Modified: float64(info.ModTime().UnixNano()) / 1e6,
		Mode:     uint32(info.Mode().Perm()), Directory: directory,
	}, nil
}

func (b *filesystemBrowser) query(query browseQuery) any {
	if err := validateBrowseQuery(query); err != nil {
		return browseErrorResult{Type: "error", Message: "Cannot read this filesystem path"}
	}
	requested := b.resolve(query.Path)
	if query.Type == "stat" {
		entry, err := b.entry(requested)
		if err != nil {
			return browseFilesystemError(err)
		}
		return browseStatResult{Type: "stat", Entry: entry}
	}
	if query.Type == "preview" {
		return b.preview(query)
	}
	if query.Type == "download" {
		return browseErrorResult{Type: "error", Message: "Downloads require the encrypted transfer handler"}
	}
	directory, err := filepath.EvalSymlinks(requested)
	if err != nil {
		return browseFilesystemError(err)
	}
	directory, err = filepath.Abs(directory)
	if err != nil {
		return browseFilesystemError(err)
	}
	file, err := os.Open(directory)
	if err != nil {
		return browseFilesystemError(err)
	}
	defer file.Close()
	offset := int64(0)
	if query.Offset != nil {
		offset = *query.Offset
	}
	position := int64(0)
	for position < offset {
		if _, err := file.ReadDir(1); err != nil {
			if err == io.EOF {
				break
			}
			return browseFilesystemError(err)
		}
		position++
	}
	entries := make([]remoteEntry, 0, pageSize)
	for len(entries) < pageSize {
		items, err := file.ReadDir(1)
		if err == io.EOF {
			break
		}
		if err != nil {
			return browseFilesystemError(err)
		}
		position++
		entry, entryErr := b.entry(filepath.Join(directory, items[0].Name()))
		if entryErr == nil {
			entries = append(entries, entry)
		}
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Directory != entries[j].Directory {
			return entries[i].Directory
		}
		return entries[i].Name < entries[j].Name
	})
	var next *int64
	if len(entries) == pageSize {
		if extra, _ := file.ReadDir(1); len(extra) != 0 {
			value := position
			next = &value
		}
	}
	parentValue := filepath.Dir(directory)
	var parent *string
	if parentValue != directory {
		parent = &parentValue
	}
	return browseListResult{Type: "list", Path: directory, Parent: parent, Offset: offset, Next: next, Entries: entries}
}

func browseFilesystemError(err error) browseErrorResult {
	message := "Cannot read this filesystem path"
	if os.IsPermission(err) {
		message = "Permission denied by the client operating system"
	} else if os.IsNotExist(err) {
		message = "Path does not exist"
	} else if strings.Contains(strings.ToLower(err.Error()), "not a directory") {
		message = "Path is not a directory"
	}
	return browseErrorResult{Type: "error", Message: message}
}

func browseHello(key []byte, browser *filesystemBrowser) map[string]any {
	return map[string]any{
		"key": base64RawURL(key), "name": browser.name, "cwd": browser.cwd, "platform": platformName(),
		"capabilities": []string{"preview", "download"},
	}
}

func base64RawURL(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func platformName() string {
	switch runtime.GOOS {
	case "darwin":
		return "darwin"
	case "windows":
		return "win32"
	default:
		return runtime.GOOS
	}
}

func (b *filesystemBrowser) preview(query browseQuery) any {
	resolved, err := filepath.EvalSymlinks(b.resolve(query.Path))
	if err != nil {
		return browseFilesystemError(err)
	}
	metadata, err := b.entry(resolved)
	if err != nil {
		return browseFilesystemError(err)
	}
	if metadata.Type != "file" {
		return browseErrorResult{Type: "error", Message: "Only regular files can be previewed"}
	}
	file, err := openReadNoFollow(resolved)
	if err != nil {
		return browseFilesystemError(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return browseFilesystemError(err)
	}
	if !info.Mode().IsRegular() {
		return browseErrorResult{Type: "error", Message: "Only regular files can be previewed"}
	}
	offset := int64(0)
	if query.Offset != nil {
		offset = *query.Offset
	}
	if offset > info.Size() {
		return browseErrorResult{Type: "error", Message: "Preview offset exceeds file size"}
	}
	length := min(int64(previewBytes), info.Size()-offset)
	data := make([]byte, length)
	defer clear(data)
	if n, err := file.ReadAt(data, offset); n != len(data) || (err != nil && err != io.EOF) {
		return browseErrorResult{Type: "error", Message: "Source file changed while previewing"}
	}
	consumed := len(data)
	encoding := "utf8"
	for at := 0; at < len(data); {
		if data[at] == 0 {
			encoding = "hex"
			break
		}
		r, size := utf8.DecodeRune(data[at:])
		if r == utf8.RuneError && size == 1 {
			if offset+int64(len(data)) < info.Size() && !utf8.FullRune(data[at:]) {
				consumed = at
				break
			}
			encoding = "hex"
			break
		}
		at += size
	}
	content := string(data[:consumed])
	if encoding == "hex" {
		var output strings.Builder
		for at := 0; at < len(data); at += 16 {
			output.WriteString(hex.EncodeToString(data[at:min(at+16, len(data))]))
			if at+16 <= len(data) {
				output.WriteByte('\n')
			}
		}
		content = output.String()
		consumed = len(data)
	}
	var next *int64
	if end := offset + int64(consumed); end < info.Size() {
		next = &end
	}
	metadata.Size = info.Size()
	metadata.Modified = float64(info.ModTime().UnixNano()) / 1e6
	return browsePreviewResult{Type: "preview", Entry: metadata, Offset: offset, Next: next, Encoding: encoding, Content: content}
}
