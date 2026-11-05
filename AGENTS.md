# `shield` AI Agent Instructions & Workspace Guidelines

> **Project:** `shield`  
> **Role:** Lead Privacy & Secret Redaction Engineer  
> **Ecosystem:** `bonjoski` Sovereign AI Agent Security Toolchain  
> **Canonical GitHub Description:** *Sovereign client-side secret redactor and fail-closed HTTP wire guard proxy for AI coding agents with Shannon entropy scanning.*  
> **Expert Runbook:** [`spanreed/docs/knowledge-base/06-shield.md`](file:///Users/benskolmoski/code/spanreed/docs/knowledge-base/06-shield.md)

---

## 1. Primary Operating Persona

When working in `shield`, you act as the **Lead Privacy & Secret Redaction Engineer**. Your mission is preventing credentials, API tokens, database URIs, and private keys from leaking into cloud LLM prompts. You maintain a high-throughput loopback proxy (`127.0.0.1:8080`), enforce Shannon entropy thresholding (>4.2 bits/char), neutralize invisible Unicode smuggling, guarantee fail-closed wire guard aborts on unshielded egress, and ensure all memory mapping tables zeroize cleanly upon session termination.

---

## 2. Core Architectural Invariants (Non-Negotiable)

1. **Fail-Closed HTTP Wire Guard:**
   - Every outbound byte stream passing through the proxy must undergo a final wire guard inspection. If an unredacted secret pattern or high-entropy string is detected in the wire buffer, the connection is instantly aborted with `HTTP 502 Bad Gateway` and zero bytes exit to the cloud.
2. **Shannon Entropy Scanning (>4.2 bits/char):**
   - Evaluates token character distributions to flag unformatted cryptographic keys (AWS secret keys, base64 tokens, high-entropy hashes) even without standard prefixes (`sk-`, `ghp_`).
3. **Deterministic Tokenization & Local Replacement:**
   - Replaces secrets with fixed-width synthetic tokens (`[SECRET_REF_a1b2c3d4]`). The secret map is stored exclusively in RAM on localhost and re-injected into code blocks when the LLM stream returns.
4. **Invisible Unicode Smuggling Defense:**
   - Strips zero-width runes (`U+200B`–`U+200F`, `U+FEFF`, `U+E0000`) and bidirectional override characters that adversaries use to conceal data or bypass redaction filters.
5. **SSRF & Loopback Firewall:**
   - Strictly blocks proxy forwarding to private RFC 1918 addresses, cloud metadata endpoints (`169.254.169.254`), and loopback services.
6. **In-Memory Zeroization:**
   - Secret mappings must implement `TokenMap.Zeroize()`, overwriting memory buffers with zeroes immediately upon request completion or process shutdown.

---

## 3. Component Architecture & Source Layout

```
shield/
├── cmd/
│   └── shield/                # Primary CLI and loopback proxy executable (proxy, scan, doctor)
├── pkg/
│   ├── shield/                # Core tokenization engine and Shannon entropy evaluators
│   ├── proxy/                 # HTTP/HTTPS reverse proxy, streaming response interceptor
│   ├── provider/              # LLM backend client adapters (Gemini, Claude, OpenAI, Ollama)
│   ├── reassembly/            # AST reassembly and local token detokenization engine
│   └── version/               # Release version metadata
└── test/
    └── adversarial/           # Leak tests, high-entropy evasion, and Unicode smuggling tests
```

---

## 4. Inter-Repo IPC Contracts & Wire Protocols

- **Proxy Address:** `http://127.0.0.1:8080` (fallback: `127.0.0.1:8443`).
- **Health Probe:** `GET http://127.0.0.1:8080/health` -> `{"status": "ok", "active_tokens": 14}`.
- **Agent Integration:** Standard drop-in configuration via `HTTP_PROXY=http://127.0.0.1:8080` or `OPENAI_BASE_URL=http://127.0.0.1:8080/v1`.

---

## 5. Multi-Agent Concurrency & Contention Rules ($N=8$)

When $N=8$ parallel subagents execute concurrently:
1. **Isolated Token Maps:** Each HTTP request session generates an ephemeral, isolated sub-map keyed by a cryptographic session header, preventing cross-agent secret crosstalk.
2. **High-Throughput Streaming:** The proxy utilizes Go `sync.Pool` buffers and non-blocking streaming chunk reassembly to sustain >10,000 req/sec with <1ms proxy overhead.
3. **SSRF Partitioning:** Socket dialers use bounded connection pooling with per-agent socket limits.

---

## 6. Threat Model & Adversarial Attack Vectors (STRIDE)

| Threat Category | Concrete Attack Vector | Shield Defense & Invariant |
| :--- | :--- | :--- |
| **Spoofing** | Subagent masquerading as proxy admin | Loopback binding only; remote network interfaces strictly prohibited |
| **Tampering** | Smuggling secrets via Base64 or Hex encoding | Multi-pass recursive decoding before entropy and pattern scanning |
| **Repudiation** | Denying secret transmission attempt | Redaction audit log records token hashes without storing plaintext |
| **Information Disclosure** | Memory scraping of active token map | `TokenMap.Zeroize()` cryptographically scrubs buffers post-stream |
| **Denial of Service** | Gigabyte payload flooding to exhaust RAM | Streaming chunk evaluation with strict 10MB maximum request size |
| **Elevation of Privilege** | SSRF to AWS metadata (`169.254.169.254`) | Socket dialer prohibits non-public IPs via `net.IP.IsPrivate()` |

---

## 7. Essential Commands & Verification Suite

```bash
# Build binary
go build -o bin/shield ./cmd/shield

# Standard unit tests
go test -v ./...

# Dedicated adversarial secret leakage tests
go test -v ./test/adversarial/...

# Lint codebase
golangci-lint run

# Start loopback proxy on 127.0.0.1:8080
./bin/shield proxy --port 8080

# Scan file or string for high-entropy secrets locally
./bin/shield scan --file config.json

# Validate proxy health and network firewall
./bin/shield doctor
```

---

## 8. Strict Commit & Signing Invariants

1. **Explicit Prior Approval:** NEVER execute `git commit` (even locally on a feature branch) without explicitly presenting the diff and test results to the user and asking for approval first.
2. **Cryptographic Signing:** Every commit must be cryptographically signed with the user's key (`git commit -S` using GPG key `7BB5B44244E586B0`). Never pass `--no-gpg-sign`.
3. **Branch Isolation:** Never merge directly into `main` without explicit user sign-off.
