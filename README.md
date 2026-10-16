# Secure Transmission

A Go rewrite of `server.mjs` and `generated-client-tui.mjs` from the sibling
`secure-transmitting` project. Work lives in this fresh repository; the original
project and its private state are not changed or copied.

## Migration checkpoints

Each completed implementation step has its own Git commit.

- [x] Start the Go module and record the migration scope.
- [x] Port the client, encrypted records, filesystem access, and resumable spools.
- [x] Implement server identity, durable storage, HTTP/WebSocket reception, and ping.
- [x] Implement authenticated browsing, previews, and server-requested downloads.
- [x] Add the interactive server TUI.
- [ ] Add personalized client generation.
- [ ] Verify interoperability, document usage, and build distributable binaries.

Protocol compatibility with the original implementation is a migration target:
X25519/HKDF-SHA256/AES-256-GCM HPKE records, pinned Ed25519 receipts, private
server state, ordered and hashed file chunks, and connection-bound browse controls.
No personalized client credentials or existing server keys belong in this repo.

Development requires Go 1.24 or newer. Client and server binaries will run without
Node.js. Optional cross-language tests use the original JavaScript project.
