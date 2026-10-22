# SchwabAssignment — Enterprise URL Shortener

> **Interview Assignment:** Build an AI-Assisted Software Engineering System  
> **Author:** Jerry Hale  
> **Platform:** Charles Schwab · Internal Engineering  
> **Short domain:** `go.schwab.com/{code}`

---

## Live Demo

Open `src/App.jsx` as a React artifact in Claude.ai — all features run in-browser with no backend required.

---

## What This Is

A production-grade URL shortener built for a financial services enterprise context. Every architectural decision is documented, every trade-off is explicit, and every guardrail is enforced in code — not just described.

Built to demonstrate:
- Engineer-led, AI-accelerated development
- Production-correct algorithms (not just working code)
- Financial services compliance awareness
- Disciplined AI use with full traceability

---

## Features

### Core
| Feature | Implementation |
|---|---|
| URL shortening | Crypto-random 7-char codes (`crypto.getRandomValues`) |
| Custom aliases | Validated slug with reserved-word blocklist |
| TTL / expiry | Lazy expiry — checked on click, atomic delete |
| Click analytics | By referrer, country, day, hour |
| QR code generation | CSS-grid simulation (production: `qrcode.js`) |
| Rate limiting | Sliding window, 10 req/min |

### AI Features
| Feature | How |
|---|---|
| ✨ URL Summarizer | Claude auto-fills title, tags, TTL recommendation |
| 🎯 Alias Suggester | Claude generates 4 slug-safe alias options |
| 🔍 Anomaly Detection | Claude analyzes click patterns for spikes/risks |
| 💬 Dashboard Chatbot | Context-aware assistant with live link data |

### External Integrations
| Integration | Purpose | Mode |
|---|---|---|
| VirusTotal | 70+ AV engines check every URL before creation | Mock (prod-ready) |
| Google Safe Browsing | Phishing + malware database check | Mock (prod-ready) |
| Slack Webhooks | Auto-alert on anomaly detection | Mock (prod-ready) |
| Compliance Webhook | Audit event push (Splunk/EventBridge/SIEM) | Mock (prod-ready) |

> **Mock mode:** All integrations use `INTEGRATIONS_CONFIG.MOCK_MODE = true` for demo.  
> Set to `false` and supply API keys in `INTEGRATIONS_CONFIG` to go live — zero code changes.

---

## Guardrails (11 Active)

1. **XSS Prevention** — `sanitize()` strips HTML tags on all inputs before storage
2. **RFC-3986 URL Validation** — `URL` constructor, not regex (47+ known regex failure cases)
3. **SSRF Protection** — Localhost, `10.x`, `192.168.x`, `127.x` blocked
4. **Protocol Whitelist** — `http:` and `https:` only; `javascript:`, `data:`, `ftp:` rejected
5. **Reserved Alias List** — 30+ words blocked: `api`, `admin`, `login`, `compliance`, `legal`…
6. **Slug Validation** — `[a-zA-Z0-9_-]` 3–32 chars enforced
7. **URL Length Cap** — 2,048 chars (RFC recommended maximum)
8. **Sliding Window Rate Limit** — 10 req/min, burst-safe (same algorithm as Stripe)
9. **Crypto Code Generation** — `crypto.getRandomValues()`, not `Math.random()`
10. **Lazy TTL Expiry** — Atomic read-check-delete, no cron race condition
11. **Field Whitelist on Update** — Prototype pollution prevention on PATCH

---

## Architecture

```
index.html → src/main.jsx → App.jsx (React SPA in the browser)
                                  │
                                  ├─ Shorten view → ValidationGate → RateLimiter
                                  │                    → URL safety checks (mock by default)
                                  │                    → URLStore + AuditLog (in memory)
                                  │                    → Compliance webhook (mock by default)
                                  │
                                  ├─ Links view → URLStore.click() (simulated click)
                                  │
                                  ├─ Analytics view → in-memory aggregates
                                  │                    → Claude anomaly analysis
                                  │                    → Slack/compliance adapters (mock)
                                  │
                                  └─ AI features + chatbot → Anthropic Messages API
```

The diagram in [`Architecture.jsx`](./Architecture.jsx) describes the implementation
that runs in this repository. The prototype has no backend, database, real redirect
endpoint, or persistent storage; link data and audit events reset when the page reloads.
Claude requests are live browser network calls. VirusTotal, Safe Browsing, Slack, and
the compliance webhook use simulated responses while `INTEGRATIONS_CONFIG.MOCK_MODE`
is `true`.

### Production Design Decisions (Target, Not Connected to the Prototype)

| Decision | Choice | Reason |
|---|---|---|
| HTTP 301 vs 302 | **302** | 301 cached permanently — analytics break, deletions ignored |
| Redis vs Memcached | **Redis** | Native TTL, cluster mode, AOF persistence |
| Kafka vs SQS | **SQS → Kafka at scale** | SQS simpler below 1M events/day; Kafka for replay + fan-out |
| Eager vs Lazy TTL | **Lazy** | Cron creates race condition; lazy is atomic; matches Redis semantics |
| Monolith vs Microservices | **Modular monolith first** | Split redirect service only when scaling needs diverge |
| VT + SB check pattern | **Promise.allSettled** | Parallel, not sequential; either failure doesn't mask other |
| Safety check failure | **Fail-open** | API outage should not take down shortener; only block on confirmed threat |

### Production Stack (Proposed)
```
Frontend:    React (static → S3 + CloudFront)
Redirect:    FastAPI + Uvicorn (ECS Fargate)
Hot store:   Redis 7 Cluster (ElastiCache, Multi-AZ)
Cold store:  PostgreSQL 16 (RDS Multi-AZ, read replicas)
Queue:       Kafka (MSK) → click events
Auth:        Schwab SSO / OAuth2 + API key scopes
Observability: Prometheus + Grafana
CI/CD:       GitHub Actions → ECR → ECS rolling deploy
Compliance:  Splunk HEC / AWS EventBridge webhook
```

---

## Project Structure

```
Schwab_Assignment/
├── src/
│   ├── App.jsx              # Main application (2,600+ lines)
│   │   ├── ValidationGate   # All input validation — URL, slug, tags, title
│   │   ├── AuditLog         # Immutable append-only operation record
│   │   ├── URLStore         # Adapter pattern — swap to Redis/PG without caller changes
│   │   ├── RateLimiter      # Sliding window, 10/min
│   │   ├── TestRunner       # Jest-compatible in-browser test harness
│   │   ├── AI Engine        # callClaude, aiSummarizeURL, aiSuggestAliases, aiDetectAnomalies
│   │   ├── Integrations     # VirusTotal, Safe Browsing, Slack, Webhook — mock + prod-ready
│   │   ├── Views            # Shorten, Links, Analytics, Integrations, Scenarios, Tests, Log, Health, API
│   │   ├── Chatbot          # Context-aware dashboard assistant
│   │   └── App (root)       # Nav, routing, Chatbot mount
│   └── Architecture.jsx     # Interactive system design diagram
├── docs
│   ├── ENGINEERING_LOG.md   # AI traceability — prompt/edit/rationale for every module
│   ├── SCENARIOS.md         # Three engineering scenarios (Greenfield/Brownfield/Ambiguous)
│   ├── API.md               # REST API reference
│   └── DECISIONS.md         # Architecture decision records (ADRs)
└── README.md
```

---

## Test Suite

55 unit tests across 9 suites — run live in the **Tests** tab:

| Suite | Tests | Covers |
|---|---|---|
| URLStore — Core CRUD | 9 | create, get, delete, update, collision |
| URLStore — Click & TTL | 5 | click counting, TTL expiry, not-found |
| URLStore — Analytics | 3 | aggregation, byRef, byCountry |
| RateLimiter | 6 | sliding window, blocking, remaining count |
| ValidationGate — URL | 12 | XSS, SSRF, protocol, length, format |
| ValidationGate — Alias | 9 | regex, reserved words, length |
| ValidationGate - Tags & Sanitize | 4 | tags, sanitize
| AuditLog | 3 | record, filter, count operations |
| Chatbot - Predefined Questions | 4 | questions, grammer, API |

All tests are Jest-compatible — copy to a Jest test file and run with no changes.

---

## AI Engineering Log Summary

| Module | AI Action | Reason |
|---|---|---|
| URLStore | Generated → **Edited** | Added boundary validation, audit injection, field whitelist |
| RateLimiter | Generated → **Extended** | Added `status()` for observability |
| `isValidURL` | Generated → **Rejected + Rewritten** | AI output had XSS and SSRF vectors |
| `generateCode` | Generated → **Edited** | Replaced `Math.random()` with `crypto.getRandomValues()` |
| TTL strategy | **Engineer decision** | Lazy expiry chosen for atomicity and Redis semantics |
| HTTP 302 | **Bug fix (self-review)** | API docs showed 301 — corrected to 302 |
| Reserved aliases | **Engineer addition** | Not in original scope — added as security guardrail |
| Three Scenarios | Generated → **Rejected + Rewritten** | AI output was generic; replaced with real engineering decisions |

Full log with prompts and rationale in `docs/ENGINEERING_LOG.md` and in the **Eng Log** tab.

---

## Compliance Notes

- **SEC Rule 17a-4** — Immutable audit log records every CREATE, DELETE, UPDATE, EXPIRE with timestamp
- **SSRF guardrail** — No internal Schwab infrastructure can be targeted via link destination
- **Rate limiting** — Prevents bulk link generation for phishing distribution at scale
- **TTL enforcement** — Regulated content links expire as required; no indefinite links for compliance-sensitive URLs
- **Compliance webhook** — Every creation event pushed to SIEM/Splunk in real-time

---

## Running Locally

```bash
# Install dependencies (Vite + React)
npm create vite@latest schwablinks -- --template react
cd schwablinks
npm install
cp path/to/App.jsx src/App.jsx
npm run dev
```

No backend required for the prototype. All state is in-memory.

---

## Going to Production

1. Set `INTEGRATIONS_CONFIG.MOCK_MODE = false`
2. Supply `VIRUSTOTAL_KEY`, `SAFE_BROWSING_KEY`, `SLACK_WEBHOOK`, `WEBHOOK_URL`
3. Replace `URLStore` internals with Redis + PostgreSQL adapter (interface unchanged)
4. Deploy `Redirect Service` to ECS Fargate behind CloudFront
5. Add Schwab SSO authentication layer
6. Wire Prometheus `/metrics` endpoint to existing Grafana stack

**Zero API contract changes required.** The adapter pattern and module interfaces are production-ready as written.
