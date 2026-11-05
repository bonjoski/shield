# Claude Code Guidelines for `shield`

> **Authoritative Ecosystem Runbook:** [`spanreed/docs/knowledge-base/06-shield.md`](file:///Users/benskolmoski/code/spanreed/docs/knowledge-base/06-shield.md)

## Build & Test Commands
- **Build Binary:** `go build -o bin/shield ./cmd/shield`
- **Unit Tests:** `go test -v ./...`
- **Adversarial Tests:** `go test -v ./test/adversarial/...`
- **Linter:** `golangci-lint run`
- **Start Proxy:** `./bin/shield proxy --port 8080`
- **Diagnostics:** `./bin/shield doctor`

## Code Style & Architectural Invariants
- Fail-closed wire guard: abort HTTP requests if raw high-entropy keys (>4.2 bits/char) reach the wire.
- Deterministic tokenization (`[SECRET_REF_...]`) with local in-memory detokenization upon stream return.
- Unicode smuggling defense: strip zero-width characters (`\u200b`, etc.).
- Strict SSRF blocking: drop requests targeting loopbacks or private IPs (`169.254.169.254`).
- Explicit in-memory scrubbing via `TokenMap.Zeroize()`.

## Commit Invariants
- Mandatory cryptographic signing with GPG key `7BB5B44244E586B0` (`git commit -S`).
- Present diff and test output for explicit user sign-off before committing.
