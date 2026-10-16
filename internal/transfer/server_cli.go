package transfer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/term"
)

const serverHelp = `Usage: server <command> [options]

Commands:
  init                          Create server keys and a trusted client profile
  serve                         Start the HTTP/WebSocket receiver
  tui                           Start the receiver with a remote filesystem TUI
  profile --endpoint <url>       Print a trusted client profile
  generate --endpoint <url> --out <file>
                                Build a personalized standalone client

Options:
  --state <directory>            Private state directory (default ./state)
  --host <address>               Listen address (default 127.0.0.1)
  --port <number>                Listen port (default 8080)
  --path <path>                  Encrypted transfer endpoint (default /)
  --max-bytes <number>           Transfer size limit (default 1073741824)
  --tui                         Enable the TUI with the serve command
  --goos <os> --goarch <arch>     Client build target (defaults to this computer)
`

// RunServer implements the receiver's command line.
func RunServer(argv []string) error {
	args, err := parseOptions(argv, map[string]bool{"tui": true}, map[string]bool{"state": true, "endpoint": true, "host": true, "port": true, "path": true, "max-bytes": true, "out": true, "goos": true, "goarch": true})
	if err != nil {
		return err
	}
	if args.command == "help" || args.command == "--help" || args.command == "-h" {
		_, err := fmt.Fprint(os.Stdout, serverHelp)
		return err
	}
	if len(args.positional) > 0 {
		return errors.New("unexpected positional arguments")
	}
	state, err := filepath.Abs(args.option("state", "./state"))
	if err != nil {
		return err
	}
	switch args.command {
	case "init":
		if _, err := initializeServer(state, args.option("endpoint", "")); err != nil {
			return err
		}
		_, err := fmt.Fprintf(os.Stdout, "Initialized %s\nTrusted client profile: %s\n", state, filepath.Join(state, "client.profile"))
		return err
	case "profile":
		p, err := loadProfile(state, args.option("endpoint", ""))
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(os.Stdout, encodeProfile(p))
		return err
	case "generate", "export-client":
		p, err := loadProfile(state, args.option("endpoint", ""))
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		output := args.option("out", "")
		if err := generateClient(ctx, p, generateOptions{output: output, goos: args.option("goos", ""), goarch: args.option("goarch", "")}); err != nil {
			return err
		}
		absolute, _ := filepath.Abs(output)
		_, err = fmt.Fprintf(os.Stdout, "Standalone client: %s\nKeep this file private: it contains the upload capability.\n", absolute)
		return err
	case "serve", "tui":
		interactive := args.command == "tui" || args.booleans["tui"]
		if interactive && (!term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd()))) {
			return errors.New("TUI requires an interactive terminal; use serve for background mode")
		}
		port, err := args.numeric("port", 8080, 0, 65535)
		if err != nil {
			return err
		}
		maxBytes, err := strconv.ParseInt(args.option("max-bytes", "1073741824"), 10, 64)
		if err != nil || maxBytes <= 0 || uint64(maxBytes) > maxSafeInteger {
			return errors.New("invalid --max-bytes")
		}
		s, err := startServer(serverOptions{state: state, host: args.option("host", "127.0.0.1"), port: port, pathname: args.option("path", "/"), maxBytes: maxBytes})
		if err != nil {
			return err
		}
		defer s.close()
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if interactive {
			return runTui(ctx, s, os.Stdin, os.Stdout)
		}
		fmt.Fprintf(os.Stdout, "Listening on %s\nReceived files: %s\n", s.url, filepath.Join(state, "received"))
		<-ctx.Done()
		return s.close()
	}
	return errors.New("unknown command; use help")
}

func loadProfile(state, endpoint string) (profile, error) {
	data, err := readPrivate(filepath.Join(state, "client.profile"), 64*1024)
	if err != nil {
		return profile{}, err
	}
	p, err := decodeProfile(string(data))
	if err != nil {
		return profile{}, err
	}
	if endpoint != "" {
		p.Endpoint = endpoint
	}
	return decodeProfile(encodeProfile(p))
}
