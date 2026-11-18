# ADR-0001: Client-Side Wire Guard Proxy & High-Entropy Secret Redaction

- **Status:** Accepted
- **Date:** 2026-10-30
- **Component:** `pkg/proxy`, `pkg/scanner`
- **Deciders:** Lead Security Architect & Network Protocols Engineer

---

## 1. Context & Problem Statement

Developer agents frequently read configuration files, `.env` files, or command output containing API keys, private keys, and session tokens, sending them directly in outbound LLM prompt requests (Anthropic, OpenAI, local models).
- Credentials leak into cloud LLM provider training/retention logs.
- Downstream LLM context windows retain plaintext tokens, making them vulnerable to prompt extraction attacks.

---

## 2. Decision Outcome

We built **Shield**, a client-side HTTP/gRPC proxy and secret sanitization engine:

1. **Local Loopback Proxy:**
   - Intercepts outbound model API requests on `localhost` (e.g. `http://127.0.0.1:8080`).
2. **High-Entropy & Pattern Sanitization:**
   - Evaluates strings against Shannon entropy thresholds and 50+ known provider key patterns (AWS, GitHub, GitLab, Slack, OpenAI, SSH private keys).
   - Automatically masks detected secrets with `[REDACTED_SECRET]` before the request leaves the developer workstation.
3. **Fail-Closed Tripwire:**
   - If an un-redactable or critical master key leak is detected, Shield drops the connection and returns HTTP 403.

---

## 3. Consequences

- **Positive:** Guarantees that private developer keys and cloud tokens are never sent to external LLM providers.
- **Negative:** Adds ~1.2ms latency overhead to model API requests.
