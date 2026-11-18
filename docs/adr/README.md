# Shield Architectural Decision Records (ADRs)

This directory documents the key architectural decisions, secret sanitization models, and proxy invariants governing [`bonjoski/shield`](https://github.com/bonjoski/shield).

## ADR Index

| ADR ID | Title | Status | Date | Scope |
| :--- | :--- | :--- | :--- | :--- |
| **[ADR-0001](0001-client-side-wire-guard-proxy-secret-redaction.md)** | **Client-Side Wire Guard Proxy & High-Entropy Secret Redaction** | `Accepted` | 2026-10-30 | `pkg/proxy`, `pkg/scanner` |

---

## Architectural Principles

1. **Local Developer DevEx Only:** Operates strictly on `localhost` via local loopback sockets or stdio streams; never deployed as an enterprise network firewall.
2. **Fail-Closed Secret Redaction:** High-entropy API keys, OAuth tokens, and private keys detected in prompts or tool responses are sanitized to `[REDACTED_SECRET]` before hitting external LLMs.
3. **Sub-1ms Streaming Latency:** High-speed streaming regex and entropy scanners inspect payloads at line rate without buffering stalls.
