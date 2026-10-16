package main

import (
	"fmt"
	"os"

	"secure-transmission/internal/transfer"
)

func main() {
	if err := transfer.RunServer(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
