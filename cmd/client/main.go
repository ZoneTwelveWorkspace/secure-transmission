package main

import (
	"fmt"
	"os"

	"secure-transmission/internal/transfer"
)

// Set only by the server's generate command. Never put credentials in source.
var pinnedProfile string

func main() {
	if pinnedProfile != "" {
		fmt.Fprintln(os.Stdout, "hit")
		sink, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		if err != nil {
			os.Exit(1)
		}
		defer sink.Close()
		os.Stdout, os.Stderr = sink, sink
	}
	if err := transfer.RunClient(os.Args[1:], pinnedProfile); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
