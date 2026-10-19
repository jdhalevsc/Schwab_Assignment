# Engineering Scenarios

> Three scenarios demonstrating decomposition, execution, and validation.  
> Required deliverable per assignment Section 5.

---

## Scenario 1: Greenfield — New System from Scratch

**Context:** Build Schwab_Assignment from zero. No existing codebase. Financial services context — all links may carry regulated content, so guardrails are non-negotiable from day one.

### Requirement Interpretation
Raw: "Build a URL shortener with core APIs, analytics, and reliability features."  
Ambiguity: "reliable" — undefined.

**Normalization process:**
- Asked: Reliable for whom? → End users clicking links.
- Asked: Measured how? → Latency (redirect speed) + uptime.
- Normalized to: p99 redirect < 10ms, 99.99% uptime (52 min downtime/year), zero data loss.
- For prototype scope: collision-free codes, rate limiting, TTL enforcement, input validation.

### Decomposition
6 independent concerns, mapped before writing code:
1. Input validation (RFC-3986 URL, slug, tags, reserved words)
2. Code generation (cryptographically random, collision-resistant)
3. Redirect + TTL enforcement (lazy expiry, HTTP 302)
4. Analytics (by referrer, country, day, hour — decoupled from redirect path)
5. Rate limiting (sliding window, burst-safe)
6. Audit logging (immutable append-only, SEC 17a-4 aligned)

### Execution Steps
1. Defined `URLStore` interface contract before implementation: `get`, `create`, `click`, `delete`, `update`, `getAnalytics`. Adapter pattern chosen — interface stays constant regardless of backing store (Map, Redis, DynamoDB).
2. Chose sliding window rate limiter over fixed window. Fixed allows 2× burst at boundary. Sliding window prevents this — same algorithm as Stripe and Cloudflare.
3. Code generation: `crypto.getRandomValues()` not `Math.random()`. 7-char code from 62-char alphabet: 3.5 trillion combinations. Auto-retry on collision (max 20 attempts).
4. TTL enforcement: lazy (on access) not eager (cron). Atomic read-check-delete. No cron race condition. Matches Redis TTL semantics — makes future swap to Redis straightforward.
5. Analytics decoupled from redirect: in production, Kafka queue between redirect service and analytics consumer. Redirect service emits event and returns immediately. Analytics lag (30s) is acceptable; redirect latency is not.

### Validation
- ✓ 6 attack vectors blocked in URL validation (XSS, SSRF, data: URI, javascript:, ftp:, empty)
- ✓ Slug regex prevents path traversal and reserved word shadowing
- ✓ Collision detection throws on duplicate alias
- ✓ Lazy TTL expiry verified: expired links return `{expired: true}` and are removed atomically
- ✓ 34 unit tests pass — all suites green

### Trade-offs
- In-memory store resets on page reload (acceptable for prototype; swap URLStore internals for production)
- QR codes are CSS simulation (production: `qrcode.js` or server-side generator)
- Analytics are synchronous in prototype (production: Kafka queue, fire-and-forget from redirect path)
- No auth layer in prototype (production: Schwab SSO + API key scopes)

---

## Scenario 2: Brownfield — Adding Analytics to Existing System

**Context:** Schwab's existing internal URL shortener (legacy Flask app) has zero analytics. Compliance team requires a full click audit trail for SEC Rule 17a-4. Requirement: add click tracking by country, referrer, and time — without breaking existing redirect behavior or modifying the redirect code path.

### Requirement Interpretation
Raw: "Add analytics to the URL shortener."  
Ambiguity: scope undefined.

**Questions asked before writing code:**
- Real-time or batch? → Batch, 30-second lag acceptable for compliance dashboards.
- Which dimensions? → Country, referrer, time bucket, user-agent.
- Breaking change allowed? → No. Existing API contract is frozen.
- New endpoints or modify existing? → New `/analytics` endpoints only; existing endpoints untouched.
- Who consumes the data? → Compliance team (regulatory), ops team (monitoring).

**Decision:** Event-emit pattern. Redirect handler emits a click event and returns immediately. Analytics consumer processes asynchronously. Redirect latency is unchanged.

### Decomposition
Identified impacted modules before touching code:
1. Redirect handler — add one fire-and-forget event emit (one line)
2. Data store — add `click_events` table (new schema, additive only)
3. API layer — add two new read endpoints (no modification to existing)
4. Analytics consumer — new service, no overlap with redirect service

### Execution Steps
1. Identified impacted modules. Confirmed zero changes needed to existing link CRUD endpoints.
2. Chose event-emit over direct write in redirect path. Redirect emits and returns — analytics processes async. Redirect latency unchanged. Analytics failure cannot cascade to redirect failure.
3. New schema: `click_events(id, code, ts, country, referrer, user_agent)`. Foreign key on `links.code`. No `ALTER TABLE` on existing `links` — safe, additive only.
4. New endpoints: `GET /api/v1/links/:code/analytics`, `GET /api/v1/analytics/summary`. Fully additive — zero modification to existing API contract.
5. Rollback plan defined before implementation: drop `click_events` table, remove single event-emit line. Two-step rollback with no data loss to existing links.

### Validation
- ✓ Zero changes to redirect path — existing redirect tests pass unchanged
- ✓ New schema is purely additive — no existing queries broken
- ✓ Analytics failure cannot cascade to redirect failure — tested by killing consumer mid-run
- ✓ Rollback is clean: drop table + remove one line — documented before implementation began

### Trade-offs
- Analytics 5–30 seconds behind real-time (acceptable for compliance reports; real-time would require ClickHouse or Flink at 3× cost)
- Country detection requires IP geolocation service (MaxMind GeoLite2) — external dependency, needs data licensing review
- User-agent parsing adds ~2ms to analytics consumer — acceptable since it is off the redirect path

---

## Scenario 3: Ambiguous — "Make It Faster"

**Context:** Requirement received: "The URL shortener is too slow. Make it faster." No metrics, no baseline, no definition of fast. Engineer must interpret, normalize, and measure before any code is written.

### Requirement Interpretation
Raw: "Make it faster."

**Normalization process (engineer-led, no code written yet):**
- Faster for whom? → End users clicking short links — not admins creating links.
- Current baseline? → No monitoring exists. First step: instrument, then measure. Never optimize blind.
- Target? → "Should feel instant." Normalized: p99 redirect latency < 10ms.
- Current stack? → PostgreSQL in the redirect hot path (SELECT on every click). No caching. No connection pooling.
- Root cause hypothesis: PostgreSQL SELECT latency 2–10ms + no pooling = p99 ~40–80ms under load.
- Decision: measure first. Hypothesis is not fact until instrumented.

### Decomposition
Three ranked improvements, ordered by impact before committing to any:
1. Redis cache layer — highest impact (0.3ms vs 6ms), self-contained, low risk
2. PostgreSQL connection pooling — medium impact (2–3ms savings), minimal change
3. CloudFront edge caching — highest total impact, but infrastructure change requiring ops coordination

### Execution Steps
1. Instrumented first — added Prometheus `/metrics` endpoint before touching any application code. Measured: p99 redirect = 47ms. Root cause confirmed: PostgreSQL SELECT on every redirect + no connection pooling + no cache.
2. Ranked improvements by impact and risk. Chose (1) Redis cache first — highest impact, lowest risk, fully reversible.
3. Implemented write-through cache: write to Redis on link creation, TTL matches link expiry (auto-GC), explicit invalidation on delete. Redis GET: 0.3ms vs PostgreSQL SELECT: 6ms. Cache hit rate target: >95%.
4. After Redis cache: p99 dropped from 47ms to 8ms. Target met (< 10ms). Stopped optimizing — no premature complexity.
5. Documented remaining headroom: connection pooling saves additional 2ms; CloudFront saves additional 4ms at edge. Available if target tightens.

### Validation
- ✓ Requirement normalized to measurable target before any code written: "faster" → "p99 < 10ms"
- ✓ Measured baseline before optimizing — confirmed root cause rather than guessing
- ✓ Smallest change first: Redis cache alone achieved the target
- ✓ Verified target met (8ms p99) before considering additional changes
- ✓ Remaining optimization headroom documented for future reference

### Trade-offs
- Redis adds infrastructure cost (~$50–200/month for ElastiCache r6g.large depending on replication)
- Redis adds operational complexity: failover configuration, AOF persistence, memory sizing
- Cache invalidation logic must be maintained alongside CRUD operations — must be tested together, not separately
- Cache staleness risk on link update/delete: mitigated by write-through on create and explicit invalidation on delete
- HTTP 302 (not 301) ensures browser never permanently caches — analytics work on every click even after cache is warm
