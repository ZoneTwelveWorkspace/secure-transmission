package transfer

import (
	"errors"
	"path/filepath"
)

func (t *Transport) downloadFromClient(connection *wsConnection, command browseCommand, browser *filesystemBrowser) any {
	selected, err := filepath.EvalSymlinks(browser.resolve(command.Query.Path))
	if err != nil {
		return browseFilesystemError(err)
	}
	var entries, skipped int
	var completed bool
	transfer, total, err := streamTransfer(t.profile, []string{selected}, command.Query.Transfer, command.ID, true, func(item transferFrame) error {
		defer clear(item.frame)
		// Keep the download on the connection that authenticated its control.
		ack, err := t.sendSocket(connection, item.frame, item.id)
		if err != nil {
			return err
		}
		if ack.Code > codeComplete || ack.Transfer != item.transfer {
			return errors.New("server rejected the download")
		}
		entries, skipped = item.entries, item.skippedLinks
		if item.phase == "commit" {
			completed = ack.Code == codeComplete && ack.Bytes == uint64(item.total)
		}
		return nil
	})
	if err != nil {
		return browseErrorResult{Type: "error", Message: "Download failed: " + err.Error()}
	}
	if !completed {
		return browseErrorResult{Type: "error", Message: "Server did not verify download completion"}
	}
	return browseDownloadResult{Type: "download", Transfer: transfer, Bytes: total, Entries: entries, SkippedLinks: skipped}
}
