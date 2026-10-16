package transfer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"
	"unicode/utf8"

	"golang.org/x/term"
)

type tuiReply struct {
	generation int
	value      any
	err        error
}
type tuiProgress struct {
	generation   int
	bytes, total uint64
}

func runTui(ctx context.Context, s *server, input, output *os.File) error {
	if !term.IsTerminal(int(input.Fd())) || !term.IsTerminal(int(output.Fd())) {
		return errors.New("TUI requires an interactive terminal; use serve for background mode")
	}
	old, err := term.MakeRaw(int(input.Fd()))
	if err != nil {
		return err
	}
	defer term.Restore(int(input.Fd()), old)
	if _, err := fmt.Fprint(output, "\x1b[?1049h\x1b[?25l"); err != nil {
		return err
	}
	defer fmt.Fprint(output, "\x1b[?25h\x1b[?1049l")
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	keys := make(chan string, 32)
	go readKeys(ctx, input, keys)
	replies := make(chan tuiReply, 16)
	progress := make(chan tuiProgress, 64)
	model := tuiModel{url: s.url}
	generation := 0
	var history, previewHistory []int64
	var jobCancel context.CancelFunc
	defer func() {
		if jobCancel != nil {
			jobCancel()
		}
	}()
	lastScreen := ""
	columns, rows := 100, 28
	redraw := func() error {
		if w, h, err := term.GetSize(int(output.Fd())); err == nil {
			columns, rows = w, h
		}
		screen := renderScreen(&model, columns, rows)
		if screen == lastScreen {
			return nil
		}
		lastScreen = screen
		_, err := fmt.Fprint(output, "\x1b[H", screen, "\x1b[J")
		return err
	}
	start := func(query browseQuery) {
		if model.client == "" || model.busy {
			return
		}
		generation++
		current, clientID := generation, model.client
		if jobCancel != nil {
			jobCancel()
		}
		jobCtx, stop := context.WithCancel(ctx)
		jobCancel = stop
		model.busy = true
		model.notice = ""
		model.saved = nil
		if query.Type == "list" {
			model.detail = nil
			model.preview = nil
		}
		if query.Type == "download" {
			model.notice = "Requesting encrypted download..."
		}
		go func() {
			var value any
			var err error
			if query.Type == "download" {
				value, err = s.download(jobCtx, clientID, query.Path, func(n, total uint64) {
					select {
					case progress <- tuiProgress{generation: current, bytes: n, total: total}:
					case <-jobCtx.Done():
					}
				})
			} else {
				value, err = s.browse(jobCtx, clientID, query)
			}
			select {
			case replies <- tuiReply{generation: current, value: value, err: err}:
			case <-ctx.Done():
			}
		}()
	}
	list := func(path string, offset int64) { start(browseQuery{Type: "list", Path: path, Offset: &offset}) }
	view := func(path, kind string, offset int64) { start(browseQuery{Type: kind, Path: path, Offset: &offset}) }
	selectClient := func(peer remoteClient) {
		if jobCancel != nil {
			jobCancel()
		}
		generation++
		model.client = peer.ID
		model.listing = nil
		model.detail = nil
		model.preview = nil
		model.saved = nil
		model.busy = false
		model.selected = 0
		history = nil
		previewHistory = nil
		if !peer.Browsing {
			model.notice = "Run this client in watch mode with browsing enabled."
			return
		}
		path := peer.Cwd
		if path == "" {
			path = "."
		}
		list(path, 0)
	}
	refreshClients := func() {
		model.clients = s.clients()
		model.clientSelected = max(0, min(model.clientSelected, len(model.clients)-1))
		found := false
		for _, peer := range model.clients {
			if peer.ID == model.client {
				found = true
				break
			}
		}
		if model.client != "" && !found {
			if jobCancel != nil {
				jobCancel()
			}
			generation++
			model.client = ""
			model.listing = nil
			model.detail = nil
			model.preview = nil
			model.saved = nil
			model.busy = false
			model.notice = "Client disconnected."
		}
		if model.client == "" {
			for i, peer := range model.clients {
				if peer.Browsing {
					model.clientSelected = i
					selectClient(peer)
					break
				}
			}
		}
	}
	refreshClients()
	if err := redraw(); err != nil {
		return err
	}
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-s.ctx.Done():
			return nil
		case <-ticker.C:
		case <-s.updates:
			refreshClients()
		case update := <-progress:
			if update.generation == generation {
				model.notice = "Downloading " + sizeLabel(update.bytes) + " / " + sizeLabel(update.total)
			}
		case reply := <-replies:
			if reply.generation != generation {
				continue
			}
			model.busy = false
			if reply.err != nil {
				model.notice = reply.err.Error()
				break
			}
			switch value := reply.value.(type) {
			case browseErrorResult:
				model.notice = value.Message
			case browseListResult:
				model.listing = &value
				model.selected = 0
				model.focusFiles = true
				model.notice = fmt.Sprintf("%d entries on this page", len(value.Entries))
				if value.Next != nil {
					model.notice += " | n: next page"
				}
			case browseStatResult:
				model.detail = &value.Entry
				model.preview = nil
			case browsePreviewResult:
				model.preview = &value
				model.detail = nil
				model.previewLine = 0
				model.notice = "Preview | n/p: content pages | d: download complete file"
			case browseDownloadResult:
				model.saved = &value
				model.detail = nil
				model.preview = nil
				model.notice = "Download complete: " + sizeLabel(uint64(value.Bytes)) + " verified."
			}
		case key := <-keys:
			if key == "ctrl-c" {
				return nil
			}
			if model.input != nil {
				switch key {
				case "escape":
					model.input = nil
				case "enter":
					path := *model.input
					model.input = nil
					history = nil
					if path == "" {
						path = "."
					}
					list(path, 0)
				case "backspace":
					value := []rune(*model.input)
					if len(value) > 0 {
						*model.input = string(value[:len(value)-1])
					}
				default:
					if utf8.RuneCountInString(key) == 1 && len(*model.input)+len(key) <= 16*1024 {
						*model.input += key
					}
				}
				break
			}
			if key == "q" {
				return nil
			}
			if key == "tab" {
				model.focusFiles = !model.focusFiles
				break
			}
			if key == "escape" {
				model.detail = nil
				model.preview = nil
				model.saved = nil
				break
			}
			if model.busy {
				break
			}
			switch key {
			case "up", "down":
				direction := 1
				if key == "up" {
					direction = -1
				}
				if !model.focusFiles {
					model.clientSelected = max(0, min(len(model.clients)-1, model.clientSelected+direction))
				} else if model.preview != nil {
					_, _, _, right := tuiDimensions(columns, rows)
					model.previewLine = max(0, min(len(wrappedText(model.preview.Content, right))-1, model.previewLine+direction))
				} else {
					model.selected = max(0, min(len(model.items())-1, model.selected+direction))
				}
			case "enter":
				if !model.focusFiles {
					if model.clientSelected < len(model.clients) {
						selectClient(model.clients[model.clientSelected])
					}
				} else if entry := model.chosenEntry(); entry != nil {
					if entry.Directory {
						history = nil
						list(entry.Path, 0)
					} else {
						previewHistory = nil
						view(entry.Path, "preview", 0)
					}
				}
			case "backspace", "left":
				if model.detail != nil || model.preview != nil || model.saved != nil {
					model.detail = nil
					model.preview = nil
					model.saved = nil
				} else if model.listing != nil && model.listing.Parent != nil {
					history = nil
					list(*model.listing.Parent, 0)
				}
			case "g":
				if model.client != "" {
					value := ""
					model.input = &value
				}
			case "v", "i":
				if entry := model.chosenEntry(); entry != nil {
					kind := "preview"
					if key == "i" {
						kind = "stat"
					}
					previewHistory = nil
					view(entry.Path, kind, 0)
				}
			case "D":
				if model.listing != nil {
					start(browseQuery{Type: "download", Path: model.listing.Path})
				}
			case "d":
				if entry := model.chosenEntry(); entry != nil {
					if model.preview == nil && model.detail == nil && entry.Name == ".." {
						model.notice = "Select an entry, or press D for the current folder."
					} else {
						start(browseQuery{Type: "download", Path: entry.Path})
					}
				}
			case "r":
				if model.preview != nil {
					view(model.preview.Entry.Path, "preview", model.preview.Offset)
				} else if model.listing != nil {
					list(model.listing.Path, model.listing.Offset)
				}
			case "n":
				if model.preview != nil && model.preview.Next != nil {
					previewHistory = append(previewHistory, model.preview.Offset)
					view(model.preview.Entry.Path, "preview", *model.preview.Next)
				} else if model.preview == nil && model.listing != nil && model.listing.Next != nil {
					history = append(history, model.listing.Offset)
					list(model.listing.Path, *model.listing.Next)
				}
			case "p":
				if model.preview != nil && len(previewHistory) > 0 {
					offset := previewHistory[len(previewHistory)-1]
					previewHistory = previewHistory[:len(previewHistory)-1]
					view(model.preview.Entry.Path, "preview", offset)
				} else if model.preview == nil && model.listing != nil && len(history) > 0 {
					offset := history[len(history)-1]
					history = history[:len(history)-1]
					list(model.listing.Path, offset)
				}
			}
		}
		if err := redraw(); err != nil {
			return err
		}
	}
}
