# PII-Safe 🔒
### Privacy Guard for Agentic AI & MCP Workflows
**GSoC 2026 · C2SI (Ceylon Computer Science Institute)**

[![Tests](https://img.shields.io/badge/tests-23%2F23%20passing-68d391)](https://github.com/hari-om65/pii-safe)
[![Python](https://img.shields.io/badge/python-3.11+-63b3ed)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-4fd1c5)](https://fastapi.tiangolo.com)
[![spaCy](https://img.shields.io/badge/spaCy-NER-f6ad55)](https://spacy.io)
[![License](https://img.shields.io/badge/license-MIT-68d391)](LICENSE)

🌐 **[Live Demo](https://hari-om65.github.io/pii-safe/)** · 💻 **[GitHub](https://github.com/hari-om65/pii-safe)**

---

## What is PII-Safe?

PII-Safe is a FastAPI middleware and MCP-compatible privacy plugin that automatically detects, redacts, and pseudonymizes PII before it reaches an LLM or gets stored in memory.
```
Raw Data → [Jailbreak Shield] → [PII Detector] → [Policy Engine]
→ [Sanitizer] → [Token Vault] → [Compliance Mapper] → [Re-ID Scorer]
→ Clean, Safe Data → LLM
```

---

## PII Types Detected & Handled

| Type | Example Input | Output |
|---|---|---|
| Email | john@example.com | EMAIL_0b9b7395 |
| Phone | +91-9876543210 | PHONE_6507f16b |
| SSN | 523-45-6789 | [REDACTED] |
| Aadhaar | 1234-5678-9012 | [REDACTED] |
| IP Address (IPv4) | 192.168.1.45 | [REDACTED] |
| IP Address (IPv6) | 2001:0db8::8a2e:370:7334 | [REDACTED] |
| API Key | sk_live_ABC123XYZ | [REDACTED] |
| JWT Token | eyJhbGci... | [REDACTED] |
| Password | P@ssw0rd123 | [REDACTED] |
| Credit Card | 4111111111111111 | [REDACTED] |
| Username | username=alice | USERNAME_xxxx |

---

## Injection & Attack Detection

| Attack | Example | Output |
|---|---|---|
| SQL Injection | ' OR 1=1; DROP TABLE | [BLOCKED: SQL injection] |
| XSS | `<script>alert()</script>` | `&lt;script&gt;` |
| Command Injection | ; ls -la && echo test | [INVALID INPUT] |
| Prompt Injection | Ignore all previous instructions | BLOCKED |
| Log Injection | FAKE_LOG_ENTRY: Admin access | [LOG INJECTION REMOVED] |

---

## Features

### Phase 1: Core Privacy Engine
- **Hybrid PII Detection** — Regex + spaCy NER (names, locations, orgs)
- **Policy-as-Code** — YAML rules: allow/redact/pseudonymize/block
- **Token Vault** — Bidirectional re-identification for agentic workflows
- **Synthetic Data** — Format-preserving fake replacements
- **Streaming Redactor** — Real-time SSE/WebSocket PII removal
- **Compliance Mapper** — Exact GDPR/HIPAA/CCPA/PCI-DSS articles
- **Re-ID Risk Scorer** — Combination-based risk calculation

### Phase 2: Agentic AI Features
- **Jailbreak Shield** — 14+ attack pattern detection
- **SQL/XSS/Command Injection Blocking**
- **JWT & Aadhaar Detection**
- **IPv6 Detection & Redaction**
- **Password Detection & Hashing**
- **Log Injection Cleaning**
- **Compliance Score Fix** — Never shows 100% when violations exist

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | /health | Server status |
| POST | /scan | Detect PII only |
| POST | /sanitize | Policy-driven sanitization |
| POST | /analyze | Full 9-engine pipeline |
| POST | /batch | Multiple texts |
| POST | /vault/protect | Tokenize PII for LLM |
| POST | /vault/restore | Restore PII in response |
| POST | /synthetic | Realistic fake data |
| POST | /jailbreak-scan | Advanced attack detection |

---

## Quick Start
```bash
git clone https://github.com/hari-om65/pii-safe
cd pii-safe
pip install -r requirements.txt
python -m spacy download en_core_web_sm
uvicorn app.main:app --reload --port 8000
```

Docker:
```bash
docker build -t pii-safe . && docker run -p 8000:8000 pii-safe
```

Tests:
```bash
python -m pytest tests/ -v
# 23 passed in 0.07s ✓
```

---

## Test Results — 23/23 Passing
```
✓ PII Detection — 7+ entity types
✓ Policy Engine — all 4 decisions
✓ Pseudonymization — scope-consistent
✓ Redaction — sensitive types always [REDACTED]
✓ Injection Shield — SQL/XSS/CMD blocked
✓ Compliance — GDPR/HIPAA/CCPA/PCI-DSS
✓ Re-ID Risk Scoring
✓ Token Vault — bidirectional
✓ Synthetic Data — format-preserving
✓ Full pipeline end-to-end

Result: 23/23 · ALL REQUIREMENTS VERIFIED ✓
```

---

## Roadmap

- [ ] Redis caching
- [ ] SQLite/Postgres audit persistence
- [ ] LangGraph integration
- [ ] CLI batch tool
- [ ] HuggingFace NER upgrade
- [ ] Dashboard v2 React + Vite

---

**Mentors:** Tharindu Ranathunga · Kavishka Fernando (C2SI)
**Built by:** Hari Om Singh · GSoC 2026 · C2SI
**Stack:** FastAPI · Python · spaCy · Docker · Redis
