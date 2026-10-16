# Secure Transmission

A Go rewrite of `server.mjs` and `generated-client-tui.mjs` from the sibling
`secure-transmitting` project. Includes encrypted messages and file transfers,
resumable uploads, persistent connections, and an interactive remote file browser.
The Go server and client interoperate with the original JavaScript application.

## Build and run

Use Go 1.24 or newer to build. Both resulting binaries run without Node.js or Go
installed on the destination computer.

```sh
make build
./bin/server init
./bin/server tui --port 8080
```

Use `./bin/server serve --port 8080` for background processes or redirected output.
`serve --tui` is equivalent to `tui`; interactive mode requires a terminal.
All server commands accept `--state <directory>` (default `./state`).

In another terminal, generate a client for the endpoint the client computer will
use. For a local test:

```sh
./bin/server generate --endpoint http://127.0.0.1:8080/ --out generated-client
./generated-client
```

For a remote computer, use the HTTPS address of your reverse proxy or tunnel in
`--endpoint`. For example, run `ngrok http 8080` separately and use its HTTPS URL.
The tunnel forwards HTTP and WebSocket traffic to the same receiver port.

Generation needs Go 1.24+ on the generating computer and access to the pinned Go
dependencies (already cached after `make build`). The server binary includes the
project source, so generation works after moving it away from this checkout.
Only the generated executable needs to be copied to the client computer.
Generation refuses to overwrite an existing output file.

Cross-compile a personalized client for another system:

```sh
./bin/server generate --endpoint https://your-endpoint.example/ --out generated-client.exe --goos windows --goarch amd64
./bin/server generate --endpoint https://your-endpoint.example/ --out generated-client-linux --goos linux --goarch amd64
./bin/server generate --endpoint https://your-endpoint.example/ --out generated-client-mac --goos darwin --goarch arm64
```

Generated clients connect in `watch` mode by default and print `hit` once at
startup, including when given `help`. That marker does not confirm a connection.
Failures return a nonzero exit code. Use `./bin/client help` and the generic
client when you need command documentation or connection/transfer diagnostics.

## Remote file browser

When a client connects in `watch` mode, the server TUI can list directories, show
metadata, preview files, and request files or entire directory trees. Browsing
starts at the client's working directory. The pinned server can read any path
accessible to that client's OS account. Use only on computers you are authorized
to manage, with that scope understood. Disable these capabilities with:

```sh
./generated-client watch --no-browse
```

Use `watch --name "Workstation"` to choose a label; no hostname is sent by default.
This app does not execute remote shell commands or modify source files.

| Key | Action |
| --- | --- |
| Up / Down | Select a client or entry; scroll a preview |
| Tab | Switch between client and file panes |
| Enter | Select a client, open a directory, or preview a file |
| v / i | Preview contents / show metadata |
| d / D | Download selected entry / entire current directory |
| Backspace / Left | Close a detail view, or go to the parent directory |
| Esc | Close a detail view or cancel path entry |
| g | Enter a client-side path |
| r | Refresh |
| n / p | Next / previous listing or preview page |
| q / Ctrl+C | Stop the TUI and receiver |

Listings have 200 entries per page. Previews read up to 64 KiB at a time,
preserve UTF-8 characters across pages, and show binary content as hex. Terminal
control sequences in remote labels, paths, and content are rendered as text.

Downloads stream ordered 128 KiB encrypted chunks and verify byte counts and
SHA-256 hashes before publication at:

```text
state/received/<transfer-id>/files/<selected-file-or-folder>
```

Empty files/directories and the tree structure are preserved. Downloads skip
nested symlinks, including broken links and cycles, and report their count.
An explicitly selected top-level symlink resolves to its target. Other special
files are rejected. Explicit `send`/`pack` uploads reject all symlinks.

## Messages, uploads, and resume

```sh
./generated-client message "Hello"
./generated-client message --stdin
./generated-client send ./document.pdf ./photos
./generated-client send ./photos --transport http --spool ./outbox
./generated-client resume --spool ./outbox
./generated-client pack ./photos --spool ./outbox
```

Spools contain encrypted records and opaque bookkeeping, and expire after
24 hours. Retrying the same spool is idempotent, including after a server restart.
Keep the same state directory and endpoint when restarting the receiver.
The client's `watch` mode retries every five minutes by default; use
`--reconnect-ms <milliseconds>` to change the interval. Ctrl+C cancels retries.
Server-requested downloads must be requested again after a disconnection.

The generic client accepts the same commands with a trusted profile:

```sh
./bin/client watch --profile-file ./state/client.profile
./bin/client send ./document.pdf --profile-file ./state/client.profile
./bin/server profile --endpoint https://your-endpoint.example/
```

Profiles can also be supplied through `--profile` or `TRANSFER_PROFILE`.
`--endpoint` changes the destination without replacing the pinned keys.

## Network and state

HTTP POST and WebSocket share `/` by default; `--path /transfer` changes that
endpoint. `GET` and `HEAD /<uuid>/ping` return an empty `204` with
`Cache-Control: no-store`, independently of `--path`. Other ping methods,
malformed paths, query strings, and trailing slashes return empty `404` responses.

Optional SOCKS5 routing with proxy-side DNS:

```sh
./generated-client watch --tor
./generated-client send ./document.pdf --tor --proxy socks5h://127.0.0.1:9150
```

Tor must run separately. A proxy failure does not trigger a direct connection.
Onion endpoints require `--tor`. Remote HTTP/WS requires `--allow-http`; loopback
HTTP and onion HTTP through Tor are allowed. TLS certificates are verified and
HTTP redirects are rejected.

The protocol keeps the original fixed [RFC 9180 HPKE suite](https://www.rfc-editor.org/rfc/rfc9180.html):
X25519, HKDF-SHA256, and AES-256-GCM, with 4096-byte padding and pinned Ed25519
receipts. Browse controls are encrypted, signed, and bound to a connection and
sequence number. Requested downloads stay bound to the authenticated client
connection. No keys are fetched from the endpoint.

Private state directories use mode 700 and files use mode 600 on Unix. Keep
`keys.json`, `client.profile`, and generated clients private. Received data and
partial transfers are plaintext on the server's private storage. Traffic timing,
volumes, and signed status information remain observable; the protocol does not
provide recipient forward secrecy. Use one receiver process per state directory.

Default limits: 1 GiB per transfer (`--max-bytes` adjusts this), 10,000 manifest
entries, 64 pending transfers, 10,000 messages, 128 network connections, and
approximately 2 MiB per encrypted record.

## Development

```sh
make test
make race
make vet
LEGACY_PROJECT=/path/to/secure-transmitting go test ./... -timeout 180s
```

The optional compatibility tests require Node.js and the original project's
development dependencies. Normal Go tests do not need the JavaScript project.
Tests cover standalone generation, both network transports, restart/resume,
authentication and tampering, connection-bound downloads, UTF-8 and binary
previews, symlinks, path validation, and terminal rendering/keyboard decoding.

`cmd/server` and `cmd/client` are executable entry points. Shared protocol,
storage, transport, filesystem, generation, and TUI code lives in
`internal/transfer`. `source.go` embeds source used by client generation.
Build output, state, and personalized clients are ignored by Git. See
`THIRD_PARTY_NOTICES.txt` for dependency license notices when distributing binaries.

## Migration checkpoints

Each completed implementation step has its own Git commit.

- [x] Start the Go module and record the migration scope.
- [x] Port the client, encrypted records, filesystem access, and resumable spools.
- [x] Implement server identity, durable storage, HTTP/WebSocket reception, and ping.
- [x] Implement authenticated browsing, previews, and server-requested downloads.
- [x] Add the interactive server TUI.
- [x] Add personalized client generation.
- [x] Verify interoperability, document usage, and build distributable binaries.

The original project and its private state were not changed or copied. Existing
Go client work in that project supplied the initial client port; missing features
and the server were implemented here. Each checkpoint is recorded in Git.
