package transfer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type manifestEntry struct {
	Path string `json:"path"`
	Type string `json:"type"`
	Size int64  `json:"size"`
}

type transferSource struct {
	entry         manifestEntry
	source        string
	info          os.FileInfo
	changedAt     int64
	hasChangeTime bool
}

type transferFrame struct {
	frame        []byte
	id           string
	expires      int64
	phase        string
	transfer     string
	total        int64
	entries      int
	skippedLinks int
}

type spoolFrame struct {
	File    string `json:"file"`
	ID      string `json:"id"`
	Digest  string `json:"digest"`
	Expires int64  `json:"expires"`
}

type spool struct {
	V         int          `json:"v"`
	Transfer  string       `json:"transfer"`
	Recipient string       `json:"recipient"`
	Frames    []spoolFrame `json:"frames"`
}

type packedTransfer struct {
	directory string
	transfer  string
	bytes     int64
	frames    int
	temporary bool
}

var invalidManifestName = regexp.MustCompile(`[\x00-\x1f\x7f\\:*?"<>|]`)

func collectSources(paths []string) ([]transferSource, int64, error) {
	sources, total, _, err := collectSourcesWithLinks(paths, false)
	return sources, total, err
}

func collectSourcesWithLinks(paths []string, skipLinks bool) ([]transferSource, int64, int, error) {
	if len(paths) == 0 {
		return nil, 0, 0, errors.New("select at least one file or directory")
	}
	skipped := 0
	sources := make([]transferSource, 0)
	var visit func(string, string) error
	visit = func(source, relative string) error {
		info, err := os.Lstat(source)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if skipLinks {
				skipped++
				return nil
			}
			return errors.New("symbolic links are not supported")
		}
		if len(sources) >= 10_000 {
			return errors.New("too many filesystem entries")
		}
		if info.IsDir() {
			changedAt, hasChangeTime := changeTime(info)
			sources = append(sources, transferSource{source: source, info: info, changedAt: changedAt,
				hasChangeTime: hasChangeTime, entry: manifestEntry{Path: relative, Type: "directory", Size: 0}})
			items, err := os.ReadDir(source)
			if err != nil {
				return err
			}
			sort.Slice(items, func(i, j int) bool { return items[i].Name() < items[j].Name() })
			for _, item := range items {
				childRelative := relative + "/" + item.Name()
				if err := visit(filepath.Join(source, item.Name()), childRelative); err != nil {
					return err
				}
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			return errors.New("only regular files and directories are supported")
		}
		changedAt, hasChangeTime := changeTime(info)
		sources = append(sources, transferSource{source: source, info: info, changedAt: changedAt,
			hasChangeTime: hasChangeTime, entry: manifestEntry{Path: relative, Type: "file", Size: info.Size()}})
		return nil
	}
	for _, selected := range paths {
		source, err := filepath.Abs(selected)
		if err != nil {
			return nil, 0, 0, err
		}
		name := filepath.Base(source)
		if name == "." || name == string(filepath.Separator) || name == "" {
			return nil, 0, 0, errors.New("select a directory below the filesystem root")
		}
		if err := visit(source, name); err != nil {
			return nil, 0, 0, err
		}
	}
	entries := make([]manifestEntry, len(sources))
	for i := range sources {
		entries[i] = sources[i].entry
	}
	total, err := validateEntries(entries)
	if err != nil {
		return nil, 0, 0, err
	}
	return sources, total, skipped, nil
}

func validateEntries(entries []manifestEntry) (int64, error) {
	if len(entries) == 0 || len(entries) > 10_000 {
		return 0, errors.New("invalid manifest")
	}
	seen := make(map[string]manifestEntry, len(entries))
	var total int64
	for _, entry := range entries {
		if entry.Path == "" || len([]byte(entry.Path)) > 1024 || invalidManifestName.MatchString(entry.Path) ||
			(entry.Type != "file" && entry.Type != "directory") || entry.Size < 0 ||
			(entry.Type == "directory" && entry.Size != 0) {
			return 0, errors.New("invalid manifest")
		}
		parts := strings.Split(entry.Path, "/")
		for _, part := range parts {
			if part == "" || part == "." || part == ".." {
				return 0, errors.New("unsafe archive path")
			}
		}
		if _, exists := seen[entry.Path]; exists {
			return 0, errors.New("unsafe archive path")
		}
		if entry.Size > math.MaxInt64-total || uint64(entry.Size) > maxSafeInteger || uint64(total+entry.Size) > maxSafeInteger {
			return 0, errors.New("invalid manifest")
		}
		total += entry.Size
		seen[entry.Path] = entry
	}
	for _, entry := range entries {
		parts := strings.Split(entry.Path, "/")
		for i := 1; i < len(parts); i++ {
			if parent, ok := seen[strings.Join(parts[:i], "/")]; ok && parent.Type == "file" {
				return 0, errors.New("conflicting archive paths")
			}
		}
	}
	return total, nil
}

func streamEncryptedTransfer(p profile, paths []string, transfer string, callback func(transferFrame) error) (string, int64, error) {
	return streamTransfer(p, paths, transfer, "", false, callback)
}

func streamTransfer(p profile, paths []string, transfer, job string, skipLinks bool, callback func(transferFrame) error) (string, int64, error) {
	sources, total, skipped, err := collectSourcesWithLinks(paths, skipLinks)
	if err != nil {
		return "", 0, err
	}
	if transfer == "" {
		transfer, err = newID()
		if err != nil {
			return "", 0, err
		}
	}
	if !idPattern.MatchString(transfer) || (job != "" && !idPattern.MatchString(job)) {
		return "", 0, errors.New("invalid transfer binding")
	}
	key, err := decodePublicEncryptionKey(p.EncryptionKey)
	if err != nil {
		return "", 0, err
	}
	makeFrame := func(phase string, operation any, data []byte) error {
		if job != "" {
			operation.(map[string]any)["job"] = job
		}
		record, err := newRecord(p.Token, operation)
		if err != nil {
			return err
		}
		frame, err := sealRecord(key, record, data)
		if err != nil {
			return err
		}
		return callback(transferFrame{
			frame: frame, id: record.ID, expires: record.Expires, phase: phase, transfer: transfer, total: total,
			entries: len(sources), skippedLinks: skipped,
		})
	}
	entries := make([]manifestEntry, len(sources))
	for i := range sources {
		entries[i] = sources[i].entry
	}
	if err := makeFrame("begin", map[string]any{"type": "begin", "transfer": transfer, "entries": entries}, nil); err != nil {
		return "", 0, err
	}
	hashes := make(map[string]string)
	buffer := make([]byte, chunkBytes)
	defer clear(buffer)
	for index, source := range sources {
		if source.entry.Type != "file" {
			continue
		}
		file, err := openReadNoFollow(source.source)
		if err != nil {
			return "", 0, err
		}
		func() {
			defer file.Close()
			current, statErr := file.Stat()
			if statErr != nil {
				err = statErr
				return
			}
			currentChangedAt, currentHasChangeTime := changeTime(current)
			if !current.Mode().IsRegular() || !os.SameFile(source.info, current) ||
				current.Size() != source.entry.Size || !current.ModTime().Equal(source.info.ModTime()) ||
				(source.hasChangeTime && (!currentHasChangeTime || currentChangedAt != source.changedAt)) {
				err = errors.New("source file changed while packing")
				return
			}
			hasher := sha256.New()
			var offset int64
			for offset < source.entry.Size {
				want := int64(len(buffer))
				if remaining := source.entry.Size - offset; remaining < want {
					want = remaining
				}
				read, readErr := file.ReadAt(buffer[:want], offset)
				if readErr != nil && readErr != io.EOF {
					err = readErr
					return
				}
				if read != int(want) {
					err = errors.New("source file changed while packing")
					return
				}
				chunk := buffer[:read]
				_, _ = hasher.Write(chunk)
				err = makeFrame("chunk", map[string]any{
					"type": "chunk", "transfer": transfer, "index": index, "offset": offset,
				}, chunk)
				clear(chunk)
				if err != nil {
					return
				}
				offset += int64(read)
			}
			after, statErr := file.Stat()
			if statErr != nil {
				err = statErr
				return
			}
			afterChangedAt, afterHasChangeTime := changeTime(after)
			if after.Size() != current.Size() || !after.ModTime().Equal(current.ModTime()) ||
				(currentHasChangeTime && (!afterHasChangeTime || afterChangedAt != currentChangedAt)) {
				err = errors.New("source file changed while packing")
				return
			}
			hashes[strconv.Itoa(index)] = hex.EncodeToString(hasher.Sum(nil))
		}()
		if err != nil {
			return "", 0, err
		}
	}
	if err := makeFrame("commit", map[string]any{"type": "commit", "transfer": transfer, "hashes": hashes}, nil); err != nil {
		return "", 0, err
	}
	return transfer, total, nil
}

func packTransfer(p profile, paths []string, spoolDirectory string) (packedTransfer, error) {
	temporary := spoolDirectory == ""
	var directory string
	var err error
	if temporary {
		directory, err = os.MkdirTemp("", "transfer-")
	} else {
		directory, err = privateDirectory(spoolDirectory)
	}
	if err != nil {
		return packedTransfer{}, err
	}
	items, err := os.ReadDir(directory)
	if err != nil {
		return packedTransfer{}, err
	}
	if len(items) != 0 {
		return packedTransfer{}, errors.New("spool directory must be empty")
	}
	state := spool{V: 1, Recipient: digest([]byte(p.EncryptionKey)), Frames: make([]spoolFrame, 0)}
	var total int64
	cleanup := true
	defer func() {
		if !cleanup {
			return
		}
		for _, frame := range state.Frames {
			_ = os.Remove(filepath.Join(directory, frame.File))
		}
		if temporary {
			_ = os.RemoveAll(directory)
		}
	}()
	transfer, bytes, err := streamEncryptedTransfer(p, paths, "", func(item transferFrame) error {
		state.Transfer = item.transfer
		total = item.total
		filename := fmt.Sprintf("%08d.bin", len(state.Frames))
		if err := writePrivate(filepath.Join(directory, filename), item.frame); err != nil {
			return err
		}
		state.Frames = append(state.Frames, spoolFrame{
			File: filename, ID: item.id, Digest: digest(item.frame), Expires: item.expires,
		})
		return nil
	})
	if err != nil {
		return packedTransfer{}, err
	}
	state.Transfer = transfer
	total = bytes
	encoded, err := json.Marshal(state)
	if err != nil {
		return packedTransfer{}, err
	}
	if err := writePrivate(filepath.Join(directory, "spool.json"), encoded); err != nil {
		return packedTransfer{}, err
	}
	cleanup = false
	return packedTransfer{directory: directory, transfer: transfer, bytes: total, frames: len(state.Frames), temporary: temporary}, nil
}

func loadSpool(directory string, p profile) (spool, string, error) {
	root, err := privateDirectory(directory)
	if err != nil {
		return spool{}, "", err
	}
	filename := filepath.Join(root, "spool.json")
	file, err := openReadNoFollow(filename)
	if err != nil {
		return spool{}, "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() > 16*1024*1024 {
		return spool{}, "", errors.New("invalid spool")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, 16*1024*1024+1))
	if err != nil {
		return spool{}, "", err
	}
	var state spool
	if err := json.Unmarshal(encoded, &state); err != nil || state.V != 1 || !idPattern.MatchString(state.Transfer) ||
		state.Recipient != digest([]byte(p.EncryptionKey)) || len(state.Frames) < 2 || len(state.Frames) > 100_000 {
		return spool{}, "", errors.New("invalid spool or different server key")
	}
	for index, frame := range state.Frames {
		if frame.File != fmt.Sprintf("%08d.bin", index) || !idPattern.MatchString(frame.ID) ||
			!digestPattern.MatchString(frame.Digest) || frame.Expires <= 0 {
			return spool{}, "", errors.New("invalid spool")
		}
		if frame.Expires <= time.Now().UnixMilli() {
			return spool{}, "", errors.New("encrypted spool expired; pack the original files again")
		}
	}
	return state, root, nil
}

func deliverSpool(transport *Transport, directory string) (receipt, error) {
	state, root, err := loadSpool(directory, transport.profile)
	if err != nil {
		return receipt{}, err
	}
	var last receipt
	for _, item := range state.Frames {
		file, err := openReadNoFollow(filepath.Join(root, item.File))
		if err != nil {
			return receipt{}, err
		}
		info, statErr := file.Stat()
		if statErr != nil || info.Size() > maxFrameBytes {
			_ = file.Close()
			return receipt{}, errors.New("invalid spool frame")
		}
		frame, readErr := io.ReadAll(io.LimitReader(file, maxFrameBytes+1))
		closeErr := file.Close()
		if readErr != nil {
			return receipt{}, readErr
		}
		if closeErr != nil {
			return receipt{}, closeErr
		}
		if digest(frame) != item.Digest {
			return receipt{}, errors.New("encrypted spool was modified")
		}
		last, err = transport.Send(frame, item.ID)
		clear(frame)
		if err != nil {
			return receipt{}, err
		}
		if last.Transfer != state.Transfer {
			return receipt{}, errors.New("receipt refers to a different transfer")
		}
	}
	if last.Code != codeComplete {
		return receipt{}, errors.New("server did not confirm completion")
	}
	return last, nil
}

func sendMessage(transport *Transport, text string) (receipt, error) {
	if len([]byte(text)) > 256*1024 {
		return receipt{}, errors.New("message exceeds 256 KiB")
	}
	key, err := decodePublicEncryptionKey(transport.profile.EncryptionKey)
	if err != nil {
		return receipt{}, err
	}
	record, err := newRecord(transport.profile.Token, map[string]any{"type": "message", "text": text})
	if err != nil {
		return receipt{}, err
	}
	frame, err := sealRecord(key, record, nil)
	if err != nil {
		return receipt{}, err
	}
	result, err := transport.Send(frame, record.ID)
	clear(frame)
	if err != nil {
		return receipt{}, err
	}
	if result.Code != codeComplete {
		return receipt{}, errors.New("server did not confirm message delivery")
	}
	return result, nil
}
