# Sovereign BYO-AI Integration Guide

`Shield` is the universal, client-side secret shielding fabric and local inference proxy for the `bonjoski` sovereign AI agent security ecosystem. It guarantees that raw credentials, private keys, database passwords, and high-entropy secrets **never egress** to cloud AI models (Gemini, Claude, OpenAI, Ollama).

---

## 1. Google Antigravity Integration

Google Antigravity (AGY) can integrate with Shield via either **Proxy Routing** or **Pre-Invocation Lifecycle Hooks**.

### Method A: Loopback Inference Proxy
Antigravity CLI and IDE agents can be configured to route outbound provider calls through the Shield proxy.

1. Start the Shield proxy daemon:
   ```bash
   shield proxy --port 8080
   ```
2. Configure Antigravity provider endpoint:
   ```bash
   export OPENAI_BASE_URL="http://127.0.0.1:8080/v1"
   export GEMINI_API_BASE_URL="http://127.0.0.1:8080"
   ```

### Method B: Antigravity Customization Hook
In `~/.super.engineering/hooks/antigravity-customization/` or workspace hooks:
```bash
#!/usr/bin/env bash
# Pre-invocation hook: intercept and sanitize prompt
SHIELDED_PROMPT=$(shield redact "$RAW_PROMPT")
echo "$SHIELDED_PROMPT"
```

---

## 2. Claude Code Integration

Claude Code natively respects custom Anthropic API base URLs.

### Step 1: Start Shield Proxy
Ensure the Shield daemon is active:
```bash
shield proxy --port 8080 --upstream-anthropic https://api.anthropic.com
```

### Step 2: Configure Environment or Shell Alias
Add the following to your shell profile (`~/.zshrc` or `~/.bashrc`):
```bash
# Route Claude Code through Shield
export ANTHROPIC_BASE_URL="http://127.0.0.1:8080"
```

Or run directly:
```bash
ANTHROPIC_BASE_URL="http://127.0.0.1:8080" claude
```

Shield intercepts all `/v1/messages` calls, tokenizes credentials into `[SECRET_REF_...]` placeholders before transmission to Anthropic, and restores placeholders upon completion.

---

## 3. Super.engineering Integration

`super.engineering` serves as the universal host chokepoint, with `~/.super.engineering/bin` prioritized in `$PATH`.

### Step 1: Install Shield Binary Shim
Symlink or install `shield` into the super.engineering binary directory:
```bash
mkdir -p ~/.super.engineering/bin
ln -sf /usr/local/bin/shield ~/.super.engineering/bin/shield
```

### Step 2: Lifecycle Hook Integration (`notify.sh`)
Configure `~/.super.engineering/hooks/notify.sh` or tool shims to run outbound payloads through Shield:
```bash
#!/usr/bin/env bash
# Intercept agent tool output before it is read by AI agents
if command -v shield >/dev/null 2>&1; then
    shield redact "$@"
else
    cat "$@"
fi
```

### Step 3: Sovereign Secret Slicing with Locksmith
Combine Shield with `locksmith slice`:
```bash
# Locksmith injects ephemeral sliced tokens into memory; Shield ensures they never escape to prompt context
locksmith slice --env .env -- shield proxy --port 8080
```

---

## 4. Cursor, Windsurf & VS Code (Cline/Continue)

For IDEs supporting custom OpenAI-compatible endpoints:

1. Start Shield proxy:
   ```bash
   shield proxy --port 8080
   ```
2. In IDE Settings:
   - **OpenAI Base URL**: `http://127.0.0.1:8080/v1`
   - **API Key**: `shield-local` (or your preferred token)
   - **Model**: `gemini-2.0-flash`, `claude-3-5-sonnet-20241022`, or `gpt-4o`

All prompts, workspace file snippets, and code completions are tokenized before leaving `127.0.0.1` and rewritten upon arrival.

---

## 5. Security Invariant: Fail-Closed Wire Guard

Every integration is backed by `shield.FailClosedWireGuard`. If a prompt contains an unshielded credential or private key:
1. Outbound network transmission is aborted immediately.
2. An error (`ErrSecretLeakageDetected`) is logged.
3. No data is sent to external AI servers.
