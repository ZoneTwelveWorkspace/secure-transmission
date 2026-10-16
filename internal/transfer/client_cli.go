package transfer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const helpText = `Usage: client <command> [options]

Commands:
  message --stdin                 Read and send a message from standard input
  message <text>                  Send a small message
  send <file-or-directory>...     Pack and upload selected filesystem entries
  pack <file-or-directory>...     Prepare an encrypted spool without networking
  resume --spool <directory>      Retry an encrypted spool without reading originals
  watch                           Connect for live status and read-only filesystem browsing

Options:
  --profile <trusted-profile>     Pinned server keys and upload capability (opaque string)
  --profile-file <file>           Read a trusted profile instead (optional)
  --endpoint <url>                Override the endpoint without changing pinned keys
  --transport ws|http             WebSocket by default; HTTP uses POST bodies
  --spool <directory>             Keep encrypted upload records in this private directory
  --tor                           Require Tor (SOCKS5 with proxy-side DNS; never falls back)
  --proxy socks5h://host:port     Override the SOCKS5 proxy (default with --tor: 127.0.0.1:9050)
  --allow-http                    Explicitly allow remote HTTP/WS without outer TLS
  --timeout <milliseconds>        Request timeout (default 15000)
  --attempts <count>              Bounded delivery retries (default 4)
  --reconnect-ms <milliseconds>   Fixed watch reconnect delay (default 300000)
  --name <label>                  Optional label in the server TUI (no hostname is sent by default)
  --no-browse                     Disable remote listings, previews, and downloads

Only the server decrypts file uploads and listings. Browse controls are encrypted and signed.
watch allows the pinned server to read/download any path this OS account can read.
`

// RunClient runs the client with an optional trusted profile embedded at build time.
func RunClient(argv []string, pinnedProfile string) error {
	if len(argv) == 0 {
		argv = []string{"help"}
		if pinnedProfile != "" {
			argv = []string{"watch"}
		}
	}
	args, err := parseArguments(argv)
	if err != nil {
		return err
	}
	if args.command == "help" || args.command == "--help" || args.command == "-h" {
		_, err := os.Stdout.WriteString(helpText)
		return err
	}
	switch args.command {
	case "message", "send", "pack", "resume", "watch":
	default:
		return errors.New("unknown command; use help")
	}

	encoded := args.option("profile", "")
	if encoded == "" {
		if profileFile := args.option("profile-file", ""); profileFile != "" {
			data, err := os.ReadFile(profileFile)
			if err != nil {
				return err
			}
			encoded = string(data)
		} else if environment := os.Getenv("TRANSFER_PROFILE"); environment != "" {
			encoded = environment
		} else {
			encoded = pinnedProfile
		}
	}
	if encoded == "" {
		return errors.New("supply a trusted --profile, --profile-file, or personalized client")
	}
	p, err := decodeProfile(encoded)
	if err != nil {
		return err
	}
	if endpoint := args.option("endpoint", ""); endpoint != "" {
		p.Endpoint = endpoint
		if _, err := validatedEndpoint(p.Endpoint); err != nil {
			return err
		}
	}
	mode := args.option("transport", "ws")
	if mode != "ws" && mode != "http" {
		return errors.New("--transport must be ws or http")
	}
	timeoutMilliseconds, err := args.numeric("timeout", 15_000, 100, 120_000)
	if err != nil {
		return err
	}
	attempts, err := args.numeric("attempts", 4, 1, 10)
	if err != nil {
		return err
	}
	reconnectMS, err := args.numeric("reconnect-ms", 300_000, 100, 86_400_000)
	if err != nil {
		return err
	}
	label := args.option("name", "")
	if len([]byte(label)) > 128 {
		return errors.New("--name is too long")
	}
	browsing := args.command == "watch" && !args.booleans["no-browse"]
	var browser *filesystemBrowser
	if browsing {
		browser, err = newFilesystemBrowser(label)
		if err != nil {
			return err
		}
	}
	transport, err := newTransport(p, networkOptions{
		mode: mode, proxy: args.option("proxy", ""), tor: args.booleans["tor"],
		allowHTTP: args.booleans["allow-http"], timeout: time.Duration(timeoutMilliseconds) * time.Millisecond,
		attempts: attempts, filesystem: browser, reconnectDelay: time.Duration(reconnectMS) * time.Millisecond,
		onConnect: func() {
			if args.command == "watch" {
				_, _ = os.Stdout.WriteString("Connected; server identity verified.\n")
			}
		},
		onEvent: func(value receipt) {
			if args.command != "watch" {
				return
			}
			status := "progress"
			if value.Code == codeComplete {
				status = "complete"
			}
			line, _ := json.Marshal(map[string]any{
				"status": status, "transfer": value.Transfer, "bytes": value.Bytes, "at": value.At,
			})
			_, _ = os.Stdout.Write(append(line, '\n'))
		},
	})
	if err != nil {
		return err
	}
	defer transport.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	signalWatchDone := make(chan struct{})
	defer close(signalWatchDone)
	go func() {
		select {
		case <-ctx.Done():
			transport.Close()
		case <-signalWatchDone:
		}
	}()

	switch args.command {
	case "message":
		if args.booleans["stdin"] && len(args.positional) != 0 {
			return errors.New("use either --stdin or message text")
		}
		if !args.booleans["stdin"] && len(args.positional) == 0 {
			return errors.New("provide a message or --stdin")
		}
		text := strings.Join(args.positional, " ")
		if args.booleans["stdin"] {
			data, err := io.ReadAll(io.LimitReader(os.Stdin, 256*1024+1))
			if err != nil {
				return err
			}
			if len(data) > 256*1024 {
				return errors.New("message exceeds 256 KiB")
			}
			text = string(data)
		}
		result, err := sendMessage(transport, text)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(os.Stdout, "Delivered %d bytes; server signature verified.\n", result.Bytes)
		return err
	case "watch":
		if len(args.positional) != 0 {
			return errors.New("watch does not take file arguments")
		}
		_, _ = fmt.Fprintf(os.Stdout, "Connecting to %s\n", p.Endpoint)
		if browsing {
			_, _ = os.Stdout.WriteString("Read-only filesystem browsing enabled for all directories this account can read. Ctrl+C disconnects.\n")
		}
		return transport.Watch(ctx)
	case "resume":
		spoolDirectory := args.option("spool", "")
		if spoolDirectory == "" {
			return errors.New("resume requires --spool")
		}
		result, err := deliverSpool(transport, spoolDirectory)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(os.Stdout, "Completed %s (%d bytes); server signature verified.\n", result.Transfer, result.Bytes)
		return err
	case "send", "pack":
		packed, err := packTransfer(p, args.positional, args.option("spool", ""))
		if err != nil {
			return err
		}
		if args.command == "pack" {
			_, err = fmt.Fprintf(os.Stdout, "Encrypted spool: %s\nTransfer: %s\n", packed.directory, packed.transfer)
			return err
		}
		result, err := deliverSpool(transport, packed.directory)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Encrypted spool retained for resume: %s\n", packed.directory)
			return err
		}
		if packed.temporary {
			if err := removeTemporarySpool(packed.directory); err != nil {
				return err
			}
		}
		_, err = fmt.Fprintf(os.Stdout, "Completed %s (%d bytes); server signature verified.\n", result.Transfer, result.Bytes)
		return err
	}
	return nil
}

func removeTemporarySpool(directory string) error {
	cleaned := filepath.Clean(directory)
	temporaryRoot := filepath.Clean(os.TempDir()) + string(filepath.Separator)
	if !strings.HasPrefix(cleaned+string(filepath.Separator), temporaryRoot) ||
		!strings.HasPrefix(filepath.Base(cleaned), "transfer-") {
		return errors.New("refusing to remove an unexpected spool directory")
	}
	return os.RemoveAll(cleaned)
}
