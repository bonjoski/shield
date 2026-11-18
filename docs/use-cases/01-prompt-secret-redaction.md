# Recipe: Outbound Prompt Secret Redaction

> **Use Case ID:** `SHI-UC-01`  
> **Target Audience:** AI Agent Developers, LLM App Builders, SecOps  
> **Platform Mechanism:** Loopback Reverse Proxy & Dynamic Redaction Engine  

---

## 1. Problem Statement

Developers frequently paste code snippets, log files, and stack traces into AI chat windows or agent loops. These inputs often contain high-entropy API tokens (AWS secrets, Stripe keys, GitHub PATs) or internal connection strings. Once submitted, these secrets are transmitted in plaintext across third-party model inference APIs (Anthropic, OpenAI, Google), violating compliance and risking exposure.

---

## 2. When to Use This

Use **Shield Proxy** whenever configuring an autonomous agent or developer workstation to interact with external model APIs. Shield runs locally on `127.0.0.1:8080`. All outbound HTTP/HTTPS requests pass through Shield, which evaluates Shannon entropy and regex token signatures, replacing matching secrets with synthetic redaction tokens (`[REDACTED_AWS_KEY]`) before transit.

---

## 3. Architecture & Dataflow

```mermaid
flowchart LR
    Agent["🤖 AI Agent / Developer<br/>(sends prompt with AWS_KEY)"] --> Proxy["🛡️ Shield Local Proxy<br/>(127.0.0.1:8080)"]
    
    Proxy --> Engine["Scanning Engine<br/>• Shannon Entropy (&gt;4.2)<br/>• 40+ Regex Patterns"]
    
    Engine --> Sanitized["Prompt with [REDACTED_AWS_KEY]"]
    Sanitized --> Cloud["☁️ Model Inference API<br/>(api.anthropic.com / api.openai.com)"]
```

---

## 4. Prerequisites

1. **Shield Installed:** `brew install bonjoski/tap/shield` (or built from source).

---

## 5. Step-by-Step Recipe

### Step 1: Start the Shield Proxy
```bash
shield proxy --port 8080
```
Expected output:
```text
🛡️ Shield Local Forward Proxy Active on 127.0.0.1:8080
Mode: INLINE_REDACTION (Shannon Entropy Threshold: 4.2)
Zero-SaaS Boundary: Active (No external telemetry)
```

### Step 2: Route Agent Traffic Through Shield
Set standard environment variables in your terminal or agent runner:
```bash
export HTTP_PROXY="http://127.0.0.1:8080"
export HTTPS_PROXY="http://127.0.0.1:8080"
```

### Step 3: Send an API Request
```bash
curl -x http://127.0.0.1:8080 https://api.openai.com/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4o", "messages": [{"role": "user", "content": "My AWS key is AKIAIOSFODNN7EXAMPLE"}]}'
```
Shield intercepts the JSON body, replaces `AKIAIOSFODNN7EXAMPLE` with `[REDACTED_AWS_KEY]`, and forwards the sanitized payload.

---

## 6. Verification & Expected Output

Verify active redaction statistics:
```bash
shield status
```
Expected output:
```text
🛡️ Shield Operational Status:
├── Intercepted Requests: 14
├── Secrets Redacted:     2 (1 AWS Key, 1 GitHub PAT)
├── Egress Denials:       0
└── Uptime:               12m 45s
```

---

## 7. Security Invariants & Blast Radius

- **Fail-Closed on TLS Tampering:** If an unrecognized CA attempts a MITM injection on loopback, Shield terminates the connection.
- **Zero Disk Persistence:** Inspected prompt bytes exist in transient memory buffers only and are never logged to disk.

---

## 8. Troubleshooting & Common Pitfalls

- **Issue:** HTTPS request fails with certificate authority error.  
  **Remediation:** Install Shield's local CA certificate:
  ```bash
  shield ca install
  ```
