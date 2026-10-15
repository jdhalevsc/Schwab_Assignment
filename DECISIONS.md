# Architecture Decision Records (ADRs)

> Every significant architectural decision, the reasoning behind it, and the trade-off accepted.

---

## ADR-001: HTTP 302 over 301 for Redirects

**Status:** Accepted  
**Date:** 2026-10-15

**Decision:** All redirects use HTTP 302 (Found), not HTTP 301 (Moved Permanently).

**Reasoning:**
- `301` is cached permanently by browsers. Once cached, the browser handles the redirect locally — the server is never contacted again.
- With `301`: click analytics stop counting (browser skips the server), deleted links still redirect for cached clients, TTL expiry is bypassed for cached clients.
- `302` ensures every click hits the server: analytics count every click, deletions are respected immediately, TTL expiry is enforced on every request.

**Trade-off accepted:** Slightly higher server load (every click hits origin vs browser-cached). At expected Schwab traffic volumes, this is negligible compared to the correctness guarantees.

---

## ADR-002: Lazy TTL Expiry over Cron-based Expiry

**Status:** Accepted  
**Date:** 2026-10-15

**Decision:** TTL expiry is checked lazily on every `click()` call — same request detects and deletes the expired link atomically.

**Reasoning:**
- Cron-based expiry (background job runs every N minutes) creates a race condition: cron deletes the link while a concurrent `click()` read is in flight. The `click()` finds a link, cron deletes it, `click()` increments a now-deleted record.
- Lazy expiry is atomic: the read, check, and delete happen in the same execution context. No race is possible.
- Matches Redis TTL semantics exactly — Redis itself uses lazy expiry. When we swap the URLStore to Redis, behavior is identical.

**Trade-off accepted:** Expired links remain in the store until someone tries to click them. Storage overhead is minimal (a few bytes per expired link). A cleanup job can optionally sweep expired links on a low-priority schedule without any correctness dependency.

---

## ADR-003: Sliding Window Rate Limiter over Fixed Window

**Status:** Accepted  
**Date:** 2026-10-15

**Decision:** Rate limiter uses sliding window algorithm (log-based), not fixed window (counter reset at interval).

**Reasoning:**
- Fixed window allows 2× the intended limit at window boundaries: 10 requests at 0:59, 10 requests at 1:00 = 20 requests in 2 seconds while the limit is 10/minute.
- Sliding window tracks request timestamps and counts only those within the last 60 seconds at any point in time. Burst at boundaries is impossible.
- Same algorithm used by Stripe, Cloudflare, and GitHub API for production rate limiting.

**Trade-off accepted:** Slightly higher memory per rate-limited client (stores timestamps vs a single counter). At expected Schwab internal usage, this is negligible.

---

## ADR-004: Adapter Pattern on URLStore

**Status:** Accepted  
**Date:** 2026-10-15

**Decision:** URLStore exposes a fixed interface contract (`get`, `create`, `click`, `delete`, `update`, `getAnalytics`, `stats`). Internals can be swapped without changing any caller.

**Reasoning:**
- Prototype uses in-memory `Map` — fast to build, zero infrastructure.
- Production needs Redis (hot redirect path) + PostgreSQL (analytics, audit).
- Without adapter pattern, swapping storage requires finding and changing every call site — risky, error-prone, and likely incomplete.
- With adapter pattern: change URLStore internals only. Zero call-site changes. Zero regression risk from the swap.

**Trade-off accepted:** Slightly more upfront design. Paid back immediately when the Redis swap is needed.

---

## ADR-005: Promise.allSettled for Parallel Safety Checks

**Status:** Accepted  
**Date:** 2026-10-15

**Decision:** VirusTotal and Google Safe Browsing checks run in parallel via `Promise.allSettled()`, not sequentially and not via `Promise.all()`.

**Reasoning:**
- Sequential: total time = VT latency + SB latency (e.g., 800ms + 400ms = 1,200ms). Unacceptable for a link creation flow.
- `Promise.all()`: parallel, but if either check throws, the other's result is lost. An API error on VT masks SB's clean result.
- `Promise.allSettled()`: parallel, each result captured independently whether resolved or rejected. VT failure doesn't prevent SB result from being used and vice versa.

**Trade-off accepted:** Both checks must complete before link creation proceeds. Total time = max(VT, SB) latency, not the sum.

---

## ADR-006: Fail-Open on Safety Check API Errors

**Status:** Accepted  
**Date:** 2026-10-15

**Decision:** If VirusTotal or Safe Browsing API calls fail (network error, timeout, API outage), link creation proceeds with a warning — not blocked.

**Reasoning:**
- Fail-closed (block on API error): a VirusTotal outage takes down SchwabLinks entirely. Ops gets paged for a third-party API issue. Unacceptable availability impact.
- Fail-open (proceed with warning on error): only confirmed threat detections block link creation. API outages are transparent to users with a logged warning.
- The safety check APIs are best-effort signals, not authoritative gatekeepers. Schwab's own URL validation (SSRF, XSS, protocol check) is the authoritative guardrail and always runs.

**Trade-off accepted:** During an API outage, a small window exists where a malicious URL could be shortened. Mitigated by: (1) Schwab's own validation still runs, (2) API outages are rare, (3) the alternative (full outage) is worse.

---

## ADR-007: Modular Monolith First, Split Later

**Status:** Accepted  
**Date:** 2026-10-15

**Decision:** Start as a single deployable unit (one FastAPI app). Split redirect service out first if/when scaling needs diverge. Add additional services only with a concrete reason.

**Reasoning:**
- Premature microservices = a distributed monolith: all the operational complexity of microservices, none of the scaling benefits.
- The redirect service is the only component with meaningfully different scaling needs (10,000× more traffic than link creation). It is the right candidate for first extraction.
- A modular monolith with clean interfaces can be split later with low risk. A distributed system cannot be un-distributed cheaply.

**Trade-off accepted:** Initial deployment is simpler but less granular. The redirect service and analytics service share a process. Acceptable until traffic validates the split.

---

## ADR-008: Crypto.getRandomValues over Math.random for Code Generation

**Status:** Accepted  
**Date:** 2026-10-15

**Decision:** Short codes are generated using `crypto.getRandomValues(Uint8Array)`, not `Math.random()`.

**Reasoning:**
- `Math.random()` is a pseudorandom number generator (PRNG). Given the same seed, it produces the same sequence. Under certain V8 versions and conditions, the seed can be inferred.
- If short codes are predictable, an attacker can enumerate `go.schwab.com/{code}` values and discover private document links, advisor meeting links, or compliance documents before they expire.
- `crypto.getRandomValues()` is cryptographically secure: seeded from OS entropy sources, output is computationally indistinguishable from random.
- One-line change. Zero performance impact. Significant security improvement.

**Trade-off accepted:** None meaningful. `crypto.getRandomValues()` is available in all modern browsers and Node.js.
