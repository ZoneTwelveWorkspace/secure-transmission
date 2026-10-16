package transfer

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTuiSanitizesRemoteTextAndFitsUnicode(t *testing.T) {
	model := tuiModel{url: "http://localhost/", client: "a", clients: []remoteClient{{ID: "a", Name: "client\x1b[31m\u202e", Browsing: true}}, preview: &browsePreviewResult{Encoding: "utf8", Content: "file\x1b]52;c;secret\a\n資料\u202e"}}
	screen := renderScreen(&model, 100, 28)
	if strings.ContainsAny(screen, "\x1b\a\u202e") {
		t.Fatal("remote text escaped the terminal renderer")
	}
	if len(strings.Split(screen, "\r\n")) != 28 {
		t.Fatal("wrong screen height")
	}
	for _, line := range strings.Split(screen, "\r\n") {
		width := 0
		for _, r := range line {
			width += characterWidth(r)
		}
		if width != 100 {
			t.Fatalf("wrong row width %d", width)
		}
	}
	if !utf8.ValidString(fitText("資料資料", 5)) {
		t.Fatal("truncation corrupted UTF-8")
	}
}

func TestTuiKeyDecoderHandlesSplitEscapeAndUTF8(t *testing.T) {
	decoder := keyDecoder{}
	if keys := decoder.feed("\x1b["); len(keys) != 0 {
		t.Fatalf("incomplete escape emitted %q", keys)
	}
	keys := decoder.feed("A\t\r\x7fDq\x03")
	if strings.Join(keys, ",") != "up,tab,enter,backspace,D,q,ctrl-c" {
		t.Fatalf("wrong keys: %q", keys)
	}
	chinese := []byte("資")
	if keys := decoder.feed(string(chinese[:2])); len(keys) != 0 {
		t.Fatal("partial UTF-8 emitted a key")
	}
	if keys := decoder.feed(string(chinese[2:])); len(keys) != 1 || keys[0] != "資" {
		t.Fatalf("wrong UTF-8 key: %q", keys)
	}
	if keys := decoder.feed("\x1b[999~"); len(keys) != 0 {
		t.Fatalf("unknown control became input: %q", keys)
	}
}
