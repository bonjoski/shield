# `Shield`

> **Sovereign Client-Side Secret Shielding & Fail-Closed Wire Guard for AI Agents**  
> Part of the `bonjoski` sovereign AI agent security ecosystem.

---

## Overview

Modern AI development tools (Antigravity, Claude Code, Cursor, Windsurf, Copilot) frequently transmit source code, environment variables, configuration files, and terminal output to remote cloud providers (Google, Anthropic, OpenAI).

**`Shield`** eliminates the risk of credential exfiltration by providing a **client-side secret redaction engine and loopback proxy**. Shield tokenizes raw credentials into fixed-width cryptographic placeholders (`[SECRET_REF_...]`) before transmission, enforces a **fail-closed wire guard** that halts outbound calls if unmasked secrets escape, and restores original values locally upon completion.

---

## Core Capabilities

- **High-Entropy Token Detection:** Shannon entropy calculation (> 4.2 bits/char) to catch unformatted high-entropy tokens and API keys.
- **Curated Credential Patterns:** High-fidelity regex rules matching Google, Anthropic, OpenAI, AWS, GitHub, Slack, DB URIs, and PEM private keys.
- **Fail-Closed Wire Guard:** Intercepts raw outbound HTTP buffers; aborts request immediately if any unshielded credential signature is detected.
- **Invisible Unicode Smuggling Defense:** Strips zero-width spaces (`\u200b`, `\u200c`, `\u200d`, `\ufeff`) used in evasion attacks.
- **In-Memory Zeroization:** Cryptographically scrubs token mapping buffers in memory (`TokenMap.Zeroize()`).
- **AST Reassembly & Syntax Verification:** Validates syntax of generated code (`go/parser`) to detect token desynchronization or corruption.
- **Drop-in Loopback Proxy:** Exposes standard `/v1/chat/completions` and `/v1/messages` on `127.0.0.1:8080`.

---

## Quickstart

### 1. Build and Run
```bash
go build -o shield ./cmd/shield
./shield proxy --port 8080
```

### 2. Redact Text Directly via CLI
```bash
./shield redact "Connect with postgres://admin:SuperSecretPass@db.internal:5432/main and AWS key AKIAIOSFODNN7EXAMPLE"
```

Output:
```
[SECRET_REF_a1b2c3d4] and [SECRET_REF_e5f6a7b8]
```

---

## Integrations

Shield seamlessly connects with your agent and developer workflows:

- **Google Antigravity:** Route provider base URLs to `http://127.0.0.1:8080` or use lifecycle pre-invocation hooks.
- **Claude Code:** Launch with `ANTHROPIC_BASE_URL="http://127.0.0.1:8080" claude`.
- **Super.engineering:** Universal host chokepoint integration via `~/.super.engineering/bin/shield` and `notify.sh`.
- **Cursor / Windsurf / VS Code:** Set OpenAI Base URL to `http://127.0.0.1:8080/v1`.

For step-by-step setup instructions, see [**Integration Guide**](docs/integrations.md).

---

## Adversarial Testing Suite

Shield includes rigorous adversarial test coverage (`test/adversarial/`):

- **ADV-01 (Unicode Smuggling):** Evasion attempts using zero-width spaces (`\u200b`, `\u200c`, `\u200d`, `\ufeff`).
- **ADV-02 (High-Entropy Scanning):** Exfiltration attempts using raw, un-prefixed cryptographic strings.
- **ADV-03 (Hallucinated Token Injection):** Detection and rejection of fabricated placeholders returned by adversarial LLMs.
- **ADV-04 (Fail-Closed Wire Guard):** Blocking outbound network transmissions when unshielded credentials exist in wire payloads.
- **ADV-05 (Cryptographic Memory Zeroization):** Verification of memory scrubbing on sensitive buffers.
- **ADV-06 (AST Reassembly Protection):** Detection of syntax corruption and desynchronization in generated code.

Run the adversarial test suite:
```bash
go test -v ./test/adversarial
```

---

## Cross-Platform Support

Shield is 100% pure Go (zero CGO) and verified across:
- **macOS** (`darwin/arm64`, `darwin/amd64`)
- **Linux** (`linux/amd64`, `linux/arm64`)
- **Windows** (`windows/amd64`)
