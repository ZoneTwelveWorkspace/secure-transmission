package transfer

import (
	"context"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type keyDecoder struct{ pending string }

func (d *keyDecoder) feed(data string) []string {
	d.pending += data
	var keys []string
	for len(d.pending) > 0 {
		value := d.pending
		if value[0] == 27 {
			if len(value) == 1 {
				break
			}
			if value[1] == '[' || value[1] == 'O' {
				end := 2
				for end < len(value) && (value[end] < 0x40 || value[end] > 0x7e) {
					end++
				}
				if end == len(value) {
					if len(value) > 64 {
						d.pending = ""
					}
					break
				}
				switch value[end] {
				case 'A':
					keys = append(keys, "up")
				case 'B':
					keys = append(keys, "down")
				case 'C':
					keys = append(keys, "right")
				case 'D':
					keys = append(keys, "left")
				}
				d.pending = value[end+1:]
				continue
			}
			keys = append(keys, "escape")
			d.pending = value[1:]
			continue
		}
		if !utf8.FullRuneInString(value) {
			break
		}
		r, size := utf8.DecodeRuneInString(value)
		d.pending = value[size:]
		switch r {
		case 3:
			keys = append(keys, "ctrl-c")
		case '\r', '\n':
			keys = append(keys, "enter")
		case '\t':
			keys = append(keys, "tab")
		case 8, 127:
			keys = append(keys, "backspace")
		default:
			if !unicode.IsControl(r) && !unicode.In(r, unicode.Cf) && r != utf8.RuneError {
				keys = append(keys, string(r))
			}
		}
	}
	return keys
}

func readKeys(ctx context.Context, input io.Reader, output chan<- string) {
	chunks := make(chan string, 1)
	go func() {
		defer close(chunks)
		buffer := make([]byte, 1024)
		for {
			n, err := input.Read(buffer)
			if n > 0 {
				select {
				case chunks <- string(buffer[:n]):
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	decoder := keyDecoder{}
	ticker := time.NewTicker(30 * time.Millisecond)
	defer ticker.Stop()
	emit := func(keys []string) bool {
		for _, key := range keys {
			select {
			case output <- key:
			case <-ctx.Done():
				return false
			}
		}
		return true
	}
	var escapedAt time.Time
	for {
		select {
		case chunk, ok := <-chunks:
			if !ok {
				_ = emit([]string{"ctrl-c"})
				return
			}
			if !emit(decoder.feed(chunk)) {
				return
			}
			if strings.HasPrefix(decoder.pending, "\x1b") {
				escapedAt = time.Now()
			}
		case now := <-ticker.C:
			if strings.HasPrefix(decoder.pending, "\x1b") && now.Sub(escapedAt) >= 30*time.Millisecond {
				if decoder.pending == "\x1b" {
					if !emit([]string{"escape"}) {
						return
					}
				}
				decoder.pending = ""
			}
		case <-ctx.Done():
			return
		}
	}
}
