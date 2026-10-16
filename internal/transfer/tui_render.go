package transfer

import (
	"fmt"
	"strings"
	"time"
	"unicode"
)

type tuiModel struct {
	url                      string
	clients                  []remoteClient
	client                   string
	focusFiles               bool
	listing                  *browseListResult
	selected, clientSelected int
	detail                   *remoteEntry
	preview                  *browsePreviewResult
	previewLine              int
	saved                    *browseDownloadResult
	busy                     bool
	notice                   string
	input                    *string
}

func safeText(text string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return '?'
		}
		return r
	}, text)
}

func characterWidth(r rune) int {
	if unicode.IsMark(r) {
		return 0
	}
	if r >= 0x1100 && (r <= 0x115f || (r >= 0x2e80 && r <= 0xa4cf) || (r >= 0xac00 && r <= 0xd7a3) || (r >= 0xf900 && r <= 0xfaff) || (r >= 0xfe10 && r <= 0xfe6f) || (r >= 0xff00 && r <= 0xff60) || (r >= 0xffe0 && r <= 0xffe6) || (r >= 0x1f300 && r <= 0x1faff) || r >= 0x20000) {
		return 2
	}
	return 1
}

func fitText(text string, width int) string {
	var out strings.Builder
	used := 0
	for _, r := range safeText(text) {
		size := characterWidth(r)
		if used+size > width {
			break
		}
		out.WriteRune(r)
		used += size
	}
	out.WriteString(strings.Repeat(" ", max(0, width-used)))
	return out.String()
}

func wrappedText(text string, width int) []string {
	text = strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n")
	var lines []string
	for _, raw := range strings.Split(text, "\n") {
		var line strings.Builder
		used := 0
		for _, r := range safeText(strings.ReplaceAll(raw, "\t", "    ")) {
			size := characterWidth(r)
			if used+size > width {
				lines = append(lines, line.String())
				line.Reset()
				used = 0
			}
			line.WriteRune(r)
			used += size
		}
		lines = append(lines, line.String())
	}
	return lines
}

func sizeLabel(size uint64) string {
	if size < 1024 {
		return fmt.Sprintf("%d B", size)
	}
	if size < 1024*1024 {
		return fmt.Sprintf("%.1f KiB", float64(size)/1024)
	}
	if size < 1024*1024*1024 {
		return fmt.Sprintf("%.1f MiB", float64(size)/(1024*1024))
	}
	return fmt.Sprintf("%.1f GiB", float64(size)/(1024*1024*1024))
}

func (m *tuiModel) items() []remoteEntry {
	if m.listing == nil {
		return nil
	}
	items := make([]remoteEntry, 0, len(m.listing.Entries)+1)
	if m.listing.Parent != nil {
		items = append(items, remoteEntry{Name: "..", Path: *m.listing.Parent, Type: "directory", Directory: true})
	}
	return append(items, m.listing.Entries...)
}

func (m *tuiModel) chosenEntry() *remoteEntry {
	if m.preview != nil {
		return &m.preview.Entry
	}
	if m.detail != nil {
		return m.detail
	}
	items := m.items()
	if m.selected >= 0 && m.selected < len(items) {
		return &items[m.selected]
	}
	return nil
}

func tuiDimensions(columns, rows int) (width, height, left, right int) {
	width = min(240, max(40, columns))
	height = min(100, max(12, rows))
	left = max(16, min(30, width*28/100))
	right = width - left - 3
	return
}

// All untrusted text is sanitized here; ANSI controls belong only to the driver.
func renderScreen(m *tuiModel, columns, rows int) string {
	width, height, left, right := tuiDimensions(columns, rows)
	peerName, path := "Select a client", "-"
	for _, peer := range m.clients {
		if peer.ID == m.client {
			peerName, path = peer.Name, peer.Cwd
			break
		}
	}
	if m.listing != nil {
		path = m.listing.Path
	}
	focus := " "
	if !m.focusFiles {
		focus = ">"
	}
	lines := []string{
		fitText(fmt.Sprintf("SECURE TRANSMISSION | Remote filesystem | %d connected", len(m.clients)), width),
		fitText("Listening: "+m.url, width), strings.Repeat("-", width),
		fitText(focus+" CLIENTS", left) + " | " + fitText(" "+peerName, right),
		fitText("", left) + " | " + fitText("Path: "+path, right), strings.Repeat("-", width),
	}
	count := height - 10
	peerStart := max(0, m.clientSelected-count+1)
	fileStart := max(0, m.selected-count+1)
	items := m.items()
	var detail []string
	if m.saved != nil {
		detail = []string{"DOWNLOAD COMPLETE", "", fmt.Sprintf("%d filesystem entries", m.saved.Entries), sizeLabel(uint64(m.saved.Bytes)) + " verified"}
		if m.saved.SkippedLinks > 0 {
			detail = append(detail, fmt.Sprintf("%d symbolic links skipped", m.saved.SkippedLinks))
		}
		detail = append(detail, "", "Saved on server:")
		detail = append(detail, wrappedText(m.saved.Destination, right)...)
		detail = append(detail, "", "Backspace / Esc: return")
	} else if m.preview != nil {
		detail = []string{"FILE CONTENT (" + strings.ToUpper(m.preview.Encoding) + ")", fmt.Sprintf("Byte offset %d | Up/Down: scroll", m.preview.Offset)}
		content := wrappedText(m.preview.Content, right)
		start := min(max(0, m.previewLine), max(0, len(content)-1))
		detail = append(detail, content[start:]...)
	} else if m.detail != nil {
		d := m.detail
		detail = []string{"FILE INFORMATION", "", "Name: " + d.Name, "Type: " + d.Type, "Size: " + sizeLabel(uint64(d.Size)), "Modified: " + time.UnixMilli(int64(d.Modified)).UTC().Format("2006-01-02 15:04:05"), fmt.Sprintf("Mode: %03o", d.Mode), "Path: " + d.Path, "", "Backspace / Esc: return"}
	}
	for row := 0; row < count; row++ {
		peerText := ""
		if at := peerStart + row; at < len(m.clients) {
			peer := m.clients[at]
			marker, selected := " ", " "
			if peer.ID == m.client {
				marker = "*"
			}
			if !m.focusFiles && at == m.clientSelected {
				selected = ">"
			}
			peerText = marker + " " + selected + " " + peer.Name
			if !peer.Browsing {
				peerText += " [status only]"
			}
		}
		fileText := ""
		if detail != nil {
			if row < len(detail) {
				fileText = detail[row]
			}
		} else if at := fileStart + row; at < len(items) {
			entry := items[at]
			marker, kind := " ", "[FILE]"
			if m.focusFiles && at == m.selected {
				marker = ">"
			}
			if entry.Directory {
				kind = "[DIR] "
			} else if entry.Type == "link" {
				kind = "[LINK]"
			}
			fileText = marker + " " + kind + " " + fitText(entry.Name, max(8, right-24))
			if !entry.Directory {
				fileText += " " + sizeLabel(uint64(entry.Size))
			}
		} else if row == 0 && m.listing == nil {
			fileText = "Waiting for a browsing-enabled client."
			if m.busy {
				fileText = "Reading directory..."
			}
		}
		lines = append(lines, fitText(peerText, left)+" | "+fitText(fileText, right))
	}
	notice := m.notice
	if notice == "" {
		notice = "Connected clients expose paths readable by their OS account."
	}
	if m.busy {
		notice = "Working... " + notice
	}
	if m.input != nil {
		notice = "Go to path: " + *m.input + "_"
	}
	lines = append(lines, strings.Repeat("-", width), fitText(notice, width), fitText("Enter: open/view  v: preview  i: info  d: download  D: current folder", width), fitText("Tab: pane  Backspace: back  g: path  r: refresh  n/p: page  q: quit", width))
	return strings.Join(lines, "\r\n")
}
