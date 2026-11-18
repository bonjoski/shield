# 💡 Shield End-User Use Cases & Recipes

> **Repository:** [`github.com/bonjoski/shield`](https://github.com/bonjoski/shield)  
> **Classification:** Developer Recipes & Task-Oriented Guides  
> **Source of Truth:** Authoritative Standard  

---

## Overview

**Shield** is a client-side secret redactor and loopback wire guard for autonomous AI agents and developer workstations. Operating as a zero-trust local forward proxy on `127.0.0.1:8080`, Shield strips high-entropy credentials, private keys, and passwords from outbound LLM inference requests, while blocking loopback SSRF attacks against internal developer services.

This directory provides task-oriented recipes for common developer and security scenarios.

---

## 📚 Recipe Catalog

| Recipe | Problem Addressed | Primary CLI Commands | Mechanism |
| :--- | :--- | :--- | :--- |
| **[01. Outbound Prompt Secret Redaction](01-prompt-secret-redaction.md)** | Intercept agent HTTP/HTTPS inference traffic on loopback to sanitize API keys and passwords before cloud transit. | `shield proxy --port 8080`<br/>`HTTP_PROXY=http://127.0.0.1:8080` | Shannon Entropy & Regex Redactor |
| **[02. Loopback SSRF Prevention Gateway](02-loopback-ssrf-prevention.md)** | Prevent autonomous web-scraping agents from probing internal developer services on `127.0.0.1` and `::1`. | `shield gateway start` | Fail-Closed Loopback Wire Guard |
| **[03. CLI Entropy Scanner & Redaction Testing](03-cli-entropy-scanner.md)** | Rapidly scan and sanitize text files, logs, or command strings for high-entropy secrets from the terminal. | `shield redact <string>` | Standalone Redaction Tool |
