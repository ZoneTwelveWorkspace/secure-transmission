package main

import (
	"fmt"
	"os"

	"secure-transmission/internal/transfer"
)

// Set only by the server's generate command. Never put credentials in source.
var pinnedProfile string

func main() {
	if err := transfer.RunClient(os.Args[1:], pinnedProfile); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
