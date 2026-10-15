import { useState } from "react";

const T = {
  bg: "#070B14",
  surface: "#0D1421",
  surfaceHover: "#131d2e",
  border: "#1a2840",
  accent: "#3B82F6",
  accentGlow: "rgba(59,130,246,0.12)",
  green: "#10B981",
  greenGlow: "rgba(16,185,129,0.12)",
  purple: "#8B5CF6",
  purpleGlow: "rgba(139,92,246,0.12)",
  orange: "#F59E0B",
  orangeGlow: "rgba(245,158,11,0.12)",
  red: "#EF4444",
  text: "#F1F5F9",
  textMuted: "#64748B",
  textDim: "#94A3B8",
  mono: "'JetBrains Mono', monospace",
  sans: "'Inter', system-ui, sans-serif",
};

const CSS = `
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: ${T.bg}; color: ${T.text}; font-family: ${T.sans}; }

  .root { min-height: 100vh; padding: 28px 20px; max-width: 1080px; margin: 0 auto; }

  .header { text-align: center; margin-bottom: 36px; }
  .header-eye { font-family: ${T.mono}; font-size: 11px; letter-spacing: 3px;
    color: ${T.accent}; text-transform: uppercase; margin-bottom: 10px; }
  .header-title { font-size: 30px; font-weight: 700; letter-spacing: -1px;
    background: linear-gradient(135deg, ${T.text} 30%, ${T.textDim} 100%);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;
    margin-bottom: 8px; }
  .header-sub { font-size: 13px; color: ${T.textMuted}; }

  /* LAYER STACK */
  .layers { display: flex; flex-direction: column; gap: 3px; margin-bottom: 32px; }
  .layer { border-radius: 10px; overflow: hidden; border: 1px solid ${T.border}; }
  .layer-header { display: flex; align-items: center; gap: 12px; padding: 12px 18px;
    cursor: pointer; user-select: none; transition: background 0.15s; }
  .layer-header:hover { background: rgba(255,255,255,0.03); }
  .layer-num { font-family: ${T.mono}; font-size: 10px; color: ${T.textMuted};
    width: 22px; text-align: right; flex-shrink: 0; }
  .layer-label { font-size: 13px; font-weight: 600; flex: 1; }
  .layer-badge { font-size: 10px; font-family: ${T.mono}; padding: 2px 8px;
    border-radius: 99px; flex-shrink: 0; }
  .layer-chevron { font-size: 10px; color: ${T.textMuted}; transition: transform 0.2s; }
  .layer-chevron.open { transform: rotate(180deg); }
  .layer-body { border-top: 1px solid ${T.border}; padding: 20px 18px;
    background: ${T.surface}; }

  /* NODE GRID */
  .node-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 10px; margin-bottom: 16px; }
  .node { border-radius: 8px; padding: 12px 14px; border: 1px solid; cursor: pointer;
    transition: all 0.15s; }
  .node:hover { transform: translateY(-2px); }
  .node.active { outline: 2px solid; }
  .node-icon { font-size: 18px; margin-bottom: 6px; }
  .node-name { font-size: 12px; font-weight: 600; margin-bottom: 3px; }
  .node-sub { font-size: 11px; opacity: 0.7; }

  /* DETAIL PANEL */
  .detail { background: ${T.bg}; border: 1px solid ${T.border}; border-radius: 8px;
    padding: 16px; margin-top: 12px; }
  .detail-title { font-size: 13px; font-weight: 700; margin-bottom: 8px;
    display: flex; align-items: center; gap: 8px; }
  .detail-body { font-size: 12px; color: ${T.textDim}; line-height: 1.7; }
  .detail-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 12px; }
  .detail-col-title { font-size: 10px; text-transform: uppercase; letter-spacing: 1px;
    color: ${T.textMuted}; margin-bottom: 6px; font-weight: 600; }
  .detail-item { font-size: 11px; color: ${T.textDim}; font-family: ${T.mono};
    padding: 3px 0; border-bottom: 1px solid ${T.border}; }

  /* FLOW DIAGRAM */
  .flow { display: flex; align-items: center; gap: 0; flex-wrap: wrap;
    margin-bottom: 24px; }
  .flow-box { background: ${T.surface}; border: 1px solid ${T.border}; border-radius: 8px;
    padding: 8px 14px; font-size: 12px; font-weight: 500; white-space: nowrap; }
  .flow-arrow { color: ${T.textMuted}; font-size: 16px; padding: 0 6px; flex-shrink: 0; }
  .flow-label { font-size: 10px; color: ${T.textMuted}; font-family: ${T.mono};
    display: block; text-align: center; margin-top: 2px; }

  /* DECISION TABLE */
  .decision-table { width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 12px; }
  .decision-table th { text-align: left; padding: 8px 12px; color: ${T.textMuted};
    font-size: 10px; text-transform: uppercase; letter-spacing: 1px;
    border-bottom: 1px solid ${T.border}; }
  .decision-table td { padding: 9px 12px; border-bottom: 1px solid rgba(26,40,64,0.6);
    color: ${T.textDim}; vertical-align: top; }
  .decision-table tr:last-child td { border-bottom: none; }
  .decision-table tr:hover td { background: ${T.surfaceHover}; }
  .mono { font-family: ${T.mono}; }
  .pill { display: inline-block; padding: 2px 8px; border-radius: 99px; font-size: 10px;
    font-family: ${T.mono}; }

  /* SLO TABLE */
  .slo-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-top: 12px; }
  .slo-card { background: ${T.bg}; border: 1px solid ${T.border}; border-radius: 8px;
    padding: 12px; text-align: center; }
  .slo-val { font-family: ${T.mono}; font-size: 20px; font-weight: 700; margin-bottom: 2px; }
  .slo-label { font-size: 10px; color: ${T.textMuted}; text-transform: uppercase;
    letter-spacing: 1px; }

  /* NAV PILLS */
  .view-nav { display: flex; gap: 6px; margin-bottom: 24px; flex-wrap: wrap; }
  .view-pill { padding: 6px 16px; border-radius: 99px; border: 1px solid ${T.border};
    background: transparent; color: ${T.textDim}; font-size: 12px; cursor: pointer;
    font-family: ${T.sans}; transition: all 0.15s; }
  .view-pill.active { background: ${T.accentGlow}; color: ${T.accent};
    border-color: rgba(59,130,246,0.4); }
  .view-pill:hover:not(.active) { border-color: ${T.accent}; color: ${T.text}; }

  /* CODE */
  .code { background: ${T.bg}; border: 1px solid ${T.border}; border-radius: 8px;
    padding: 14px; font-family: ${T.mono}; font-size: 11px; color: #93c5fd;
    overflow-x: auto; white-space: pre; line-height: 1.7; margin-top: 10px; }

  @media (max-width: 640px) {
    .slo-grid { grid-template-columns: 1fr 1fr; }
    .detail-row { grid-template-columns: 1fr; }
    .node-grid { grid-template-columns: 1fr 1fr; }
  }
`;

// ─── Data ─────────────────────────────────────────────────────────────────────
const LAYERS = [
  {
    id: "client",
    num: "01",
    label: "Client Layer",
    badge: "Public",
    badgeColor: T.accent,
    badgeBg: T.accentGlow,
    headerBg: "rgba(59,130,246,0.05)",
    nodes: [
      { icon: "🌐", name: "Browser / Mobile", sub: "React SPA", color: T.accent, bg: T.accentGlow,
        detail: "The React SPA is served as a static bundle from S3+CloudFront. No server-side rendering needed — all routing is client-side. CDN handles global distribution with edge caching.",
        why: "Static hosting = zero server cost for the UI layer. CloudFront puts the bundle within 20ms of 99% of users.",
        tradeoff: "First meaningful paint depends on JS bundle size. Mitigate with code-splitting and lazy loading per route.",
        specs: ["React 18 + Vite", "Bundle < 150KB gzipped", "CDN: CloudFront", "Auth: Cognito / Auth0"] },
      { icon: "📱", name: "Mobile App", sub: "iOS / Android", color: T.accent, bg: T.accentGlow,
        detail: "Native or React Native client consuming the same REST API. Deep-link handling routes short URLs through the app's in-app browser with analytics passthrough.",
        why: "Same API contract as web — no separate mobile backend needed.",
        tradeoff: "App Store review cycles slow hotfixes. Feature flags mitigate.",
        specs: ["React Native / Swift", "Same REST API", "Deep link support", "Offline queue for creation"] },
      { icon: "⌨️", name: "CLI / SDK", sub: "curl / Python / Node", color: T.accent, bg: T.accentGlow,
        detail: "Developers use the API key directly via curl or official SDKs. Rate limiting is enforced identically — no special treatment for CLI callers.",
        why: "Power users need programmatic access. SDK reduces integration friction.",
        tradeoff: "SDK maintenance burden. Solve with OpenAPI codegen.",
        specs: ["Python SDK", "Node.js SDK", "OpenAPI 3.1 spec", "API key auth"] },
    ]
  },
  {
    id: "edge",
    num: "02",
    label: "Edge & Gateway Layer",
    badge: "Global",
    badgeColor: T.green,
    badgeBg: T.greenGlow,
    headerBg: "rgba(16,185,129,0.05)",
    nodes: [
      { icon: "☁️", name: "CloudFront CDN", sub: "Edge cache + WAF", color: T.green, bg: T.greenGlow,
        detail: "All traffic hits CloudFront first. Warm short-URL redirects are cached at the edge — no origin hit needed. Cache TTL matches the link's own TTL. WAF rules block SQL injection, XSS, and bot floods.",
        why: "Redirect latency drops from ~80ms (origin) to ~4ms (edge). This is the most impactful single infrastructure decision.",
        tradeoff: "Cache invalidation when a link is deleted or expired must propagate to all 400+ edge locations. Use CloudFront invalidation API — costs $0.005/path.",
        specs: ["400+ edge locations", "Cache-Control headers", "WAF: AWS WAF", "Avg redirect: 4ms"] },
      { icon: "🔀", name: "API Gateway", sub: "Rate limit · Auth · Route", color: T.green, bg: T.greenGlow,
        detail: "AWS API Gateway (or Kong) sits in front of the application servers. Handles API key validation, request throttling, and routes traffic to the correct microservice.",
        why: "Keeps auth and rate limiting out of application code. Centralized policy = consistent enforcement.",
        tradeoff: "Adds ~1ms latency. Acceptable. API Gateway has its own rate limit ceiling (10,000 rps default) — request quota increase for high-traffic.",
        specs: ["AWS API Gateway v2", "JWT + API key auth", "10K rps default", "Custom domain + SSL"] },
      { icon: "🛡️", name: "DDoS Shield", sub: "AWS Shield Advanced", color: T.green, bg: T.greenGlow,
        detail: "AWS Shield Advanced provides always-on DDoS detection and automatic mitigation. URL shorteners are high-value DDoS targets because a single popular short link can drive massive redirect storms.",
        why: "A 10Gbps flood against an unprotected redirect service takes it down in seconds.",
        tradeoff: "$3,000/month flat fee. Justified at scale. Under 10M monthly redirects, Shield Standard (free) is sufficient.",
        specs: ["Layer 3/4 mitigation", "Layer 7 via WAF", "SLA: 99.99%", "DDoS cost protection"] },
    ]
  },
  {
    id: "app",
    num: "03",
    label: "Application Layer",
    badge: "Core Logic",
    badgeColor: T.purple,
    badgeBg: T.purpleGlow,
    headerBg: "rgba(139,92,246,0.05)",
    nodes: [
      { icon: "⚡", name: "Redirect Service", sub: "FastAPI · Critical path", color: T.purple, bg: T.purpleGlow,
        detail: "The hottest, most latency-sensitive service. Receives /:code, looks up Redis (microseconds), checks TTL, increments click counter async, then issues a 301. Nothing else runs in this path.",
        why: "Redirect is called 100x more than any other endpoint. It must be fast and simple. Complexity belongs elsewhere.",
        tradeoff: "301 (permanent) vs 302 (temporary). Use 302 for trackable links so browsers don't cache — otherwise analytics break.",
        specs: ["FastAPI + Uvicorn", "Redis lookup: <1ms", "HTTP 302 redirect", "Async click event emit"] },
      { icon: "🔧", name: "Link Service", sub: "CRUD · Validation · Aliases", color: T.purple, bg: T.purpleGlow,
        detail: "Handles create, read, update, delete for links. Runs all validation: URL format, slug regex, collision detection, TTL bounds. Writes to PostgreSQL as source of truth, then warms Redis.",
        why: "Separating CRUD from redirect keeps the redirect path thin. Link service can be slow; redirect service cannot.",
        tradeoff: "Write-through cache (write to PG + Redis together) vs write-behind (async). Write-through chosen for consistency — no stale redirect after creation.",
        specs: ["FastAPI", "PostgreSQL write", "Redis warm on create", "Idempotent PUT"] },
      { icon: "📊", name: "Analytics Service", sub: "Kafka consumer · Aggregator", color: T.purple, bg: T.purpleGlow,
        detail: "Consumes click events from Kafka. Aggregates by link, country, referrer, and time bucket. Writes rollups to PostgreSQL. Separate from the redirect path — analytics lag is acceptable, redirect latency is not.",
        why: "Decoupling via Kafka means a analytics outage never slows down redirects.",
        tradeoff: "Analytics can be 5–30 seconds behind real-time. Acceptable for dashboards. If real-time is required, use ClickHouse or Apache Flink.",
        specs: ["Kafka consumer", "5s event lag OK", "ClickHouse option", "Rollups: 1min / 1hr / 1d"] },
      { icon: "🔑", name: "Auth Service", sub: "JWT · API keys · Scopes", color: T.purple, bg: T.purpleGlow,
        detail: "Issues and validates JWT tokens and API keys. Scopes control what each key can do: read-only, create-only, or admin. API keys are hashed (bcrypt) at rest — never stored in plaintext.",
        why: "Centralized auth means one place to revoke a compromised key across all services.",
        tradeoff: "JWT expiry vs refresh token complexity. 15-min access token + 7-day refresh is the standard balance.",
        specs: ["JWT RS256", "API keys: bcrypt hashed", "Scopes: read/write/admin", "Key rotation support"] },
    ]
  },
  {
    id: "data",
    num: "04",
    label: "Data Layer",
    badge: "Persistence",
    badgeColor: T.orange,
    badgeBg: T.orangeGlow,
    headerBg: "rgba(245,158,11,0.05)",
    nodes: [
      { icon: "⚡", name: "Redis Cluster", sub: "Hot path · TTL native", color: T.orange, bg: T.orangeGlow,
        detail: "Primary lookup store for the redirect path. Key: short code. Value: long URL + metadata. Redis TTL matches link expiry — automatic garbage collection with zero application code. Cluster mode for HA.",
        why: "Redis GET is sub-millisecond. PostgreSQL SELECT is 2–10ms. At 10M redirects/day, that difference is the entire user experience.",
        tradeoff: "Redis is expensive per GB. Only store the hot redirect record — not full analytics. Full record lives in PostgreSQL.",
        specs: ["Redis 7 Cluster", "r6g.large nodes", "AOF persistence", "Multi-AZ replica"] },
      { icon: "🐘", name: "PostgreSQL", sub: "Source of truth · Analytics", color: T.orange, bg: T.orangeGlow,
        detail: "Primary relational store. Two schemas: links (source of truth for all link metadata) and analytics (click events, aggregated rollups). Read replicas handle dashboard query load without touching the write primary.",
        why: "Relational integrity matters: foreign keys, transactions, and complex analytics queries need SQL.",
        tradeoff: "PostgreSQL analytics queries get slow past 100M rows. Partition click_events by month. Beyond 1B rows, migrate analytics to ClickHouse.",
        specs: ["PostgreSQL 16", "RDS Multi-AZ", "Read replicas ×2", "Partitioned by month"] },
      { icon: "📨", name: "Kafka", sub: "Click event stream", color: T.orange, bg: T.orangeGlow,
        detail: "Message queue between the redirect service and analytics service. Redirect service emits a click event (code, timestamp, IP, user-agent, referrer) and returns immediately. Kafka buffers and delivers to analytics consumers.",
        why: "Decouples the latency-critical redirect path from the slower analytics pipeline. Redirect service does not wait for analytics to finish.",
        tradeoff: "Adds operational complexity. Below 1M events/day, SQS is simpler and cheaper. Kafka shines at 10M+ events/day.",
        specs: ["MSK (managed Kafka)", "3 brokers", "7-day retention", "Topic: link.clicks"] },
      { icon: "🗄️", name: "S3 + Glacier", sub: "Long-term analytics archive", color: T.orange, bg: T.orangeGlow,
        detail: "Monthly analytics rollups are exported to S3 as Parquet files. Older than 90 days moves to Glacier. Athena runs SQL directly on S3 for ad-hoc historical queries without loading into PostgreSQL.",
        why: "Storing 3-year analytics in PostgreSQL is expensive. S3 is 95% cheaper per GB. Athena makes it queryable on demand.",
        tradeoff: "Athena queries take seconds, not milliseconds. Acceptable for historical exports, not live dashboards.",
        specs: ["S3 Standard → Glacier", "Parquet format", "Athena queryable", "Cost: ~$0.023/GB/month"] },
    ]
  },
  {
    id: "ops",
    num: "05",
    label: "Observability & Ops",
    badge: "Your Stack",
    badgeColor: T.accent,
    badgeBg: T.accentGlow,
    headerBg: "rgba(59,130,246,0.04)",
    nodes: [
      { icon: "📈", name: "Prometheus + Grafana", sub: "Metrics · Alerts · Dashboards", color: T.accent, bg: T.accentGlow,
        detail: "Every service exposes a /metrics endpoint. Prometheus scrapes every 15s. Grafana dashboards show redirect latency (p50/p95/p99), error rates, Redis hit ratio, Kafka consumer lag, and active link count.",
        why: "Your Xolaris-AI CIGMON stack is built on this. Direct fit.",
        tradeoff: "Prometheus storage is local — not durable for long-term retention. Use Thanos or Grafana Mimir for multi-month retention.",
        specs: ["15s scrape interval", "30-day local retention", "Thanos for long-term", "PagerDuty alerts"] },
      { icon: "📋", name: "Structured Logging", sub: "JSON · CloudWatch · Loki", color: T.accent, bg: T.accentGlow,
        detail: "All services log structured JSON to stdout. ECS picks it up and ships to CloudWatch Logs. Grafana Loki aggregates and makes logs searchable alongside metrics in the same dashboard.",
        why: "Structured logs are queryable. Plain text logs are grep. At scale, grep doesn't scale.",
        tradeoff: "CloudWatch Logs costs add up at high volume. Use log sampling for debug-level; always log errors and warnings.",
        specs: ["JSON structured logs", "CloudWatch + Loki", "30-day retention", "Correlation IDs"] },
      { icon: "🔍", name: "Distributed Tracing", sub: "AWS X-Ray · OpenTelemetry", color: T.accent, bg: T.accentGlow,
        detail: "Every request gets a trace ID that follows it through API Gateway → Redirect Service → Redis → Kafka. When a redirect is slow, you can see exactly which hop added latency.",
        why: "You cannot debug a distributed system without traces. Logs tell you what happened; traces tell you why it was slow.",
        tradeoff: "100% trace sampling is expensive. Use 1% sampling in production, 100% for error traces.",
        specs: ["OpenTelemetry SDK", "AWS X-Ray backend", "1% sampling prod", "100% error traces"] },
      { icon: "🚀", name: "CI/CD Pipeline", sub: "GitHub Actions · ECS Deploy", color: T.accent, bg: T.accentGlow,
        detail: "Push to main → GitHub Actions runs tests → builds Docker image → pushes to ECR → triggers ECS rolling deploy. Blue/green deployment with automatic rollback if error rate spikes above 1% within 5 minutes.",
        why: "Manual deploys are the #1 cause of production incidents. Automate everything, test in the pipeline.",
        tradeoff: "Blue/green doubles compute cost during deploy window (~10 min). Worth it for zero-downtime and instant rollback.",
        specs: ["GitHub Actions", "Docker + ECR", "ECS rolling deploy", "Auto-rollback on error spike"] },
    ]
  },
];

const DECISIONS = [
  { decision: "HTTP 302 vs 301 for redirects", chosen: "302 Temporary", why: "301 is cached by browsers forever — analytics break because the browser never hits the server again. 302 ensures every click is counted.", risk: "Slightly slower (no browser cache), but correct." },
  { decision: "Redis vs Memcached", chosen: "Redis", why: "Native TTL support means link expiry is automatic. No cleanup job needed. Redis also supports clustering and persistence.", risk: "Redis is more expensive. Acceptable trade-off." },
  { decision: "Kafka vs SQS for click events", chosen: "SQS to start, Kafka at scale", why: "SQS is simpler and cheaper below 1M events/day. Kafka is better above 10M — replay, multiple consumers, partitioning.", risk: "Migration from SQS to Kafka is a breaking change. Plan the interface contract early." },
  { decision: "PostgreSQL vs DynamoDB", chosen: "PostgreSQL", why: "Link management needs foreign keys, transactions, and complex analytics queries. DynamoDB doesn't support these well.", risk: "PostgreSQL requires more operational care. Use RDS to manage it." },
  { decision: "Monolith vs Microservices", chosen: "Modular monolith first", why: "Start with one deployable unit (FastAPI). Split redirect service out first — it has different scaling needs. Add services only when you have a real reason.", risk: "Premature microservices = distributed monolith. Worse than the original." },
  { decision: "301 cache invalidation on delete", chosen: "Serve 410 Gone", why: "When a link is deleted, cached 301s in browsers can't be recalled. Return 410 Gone from origin — at least new visitors see an error.", risk: "Users with cached 301s will still redirect even after deletion. Unavoidable without 302." },
];

const SLOs = [
  { val: "< 10ms", label: "Redirect P99", color: T.green },
  { val: "99.99%", label: "Uptime SLO", color: T.green },
  { val: "< 500ms", label: "Create P99", color: T.accent },
  { val: "< 30s", label: "Analytics Lag", color: T.orange },
];

const INFRA_CODE = `# docker-compose.yml (local dev mirrors production topology)
services:
  redirect:
    build: ./services/redirect
    ports: ["8001:8000"]
    environment:
      REDIS_URL: redis://redis:6379
      KAFKA_BROKERS: kafka:9092
    depends_on: [redis, kafka]

  link-service:
    build: ./services/link
    ports: ["8002:8000"]
    environment:
      DATABASE_URL: postgresql://user:pass@postgres:5432/urlshortener
      REDIS_URL: redis://redis:6379

  analytics:
    build: ./services/analytics
    environment:
      KAFKA_BROKERS: kafka:9092
      DATABASE_URL: postgresql://user:pass@postgres:5432/urlshortener

  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: urlshortener
      POSTGRES_USER: user
      POSTGRES_PASSWORD: pass

  kafka:
    image: confluentinc/cp-kafka:7.5.0
    environment:
      KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
      KAFKA_AUTO_CREATE_TOPICS_ENABLE: "true"`;

// ─── Components ───────────────────────────────────────────────────────────────
function Node({ node, isActive, onClick }) {
  return (
    <div className={`node ${isActive ? "active" : ""}`}
      style={{ background: isActive ? node.bg : "rgba(255,255,255,0.02)", borderColor: isActive ? node.color : T.border, outlineColor: node.color }}
      onClick={onClick}>
      <div className="node-icon">{node.icon}</div>
      <div className="node-name" style={{ color: isActive ? node.color : T.text }}>{node.name}</div>
      <div className="node-sub">{node.sub}</div>
    </div>
  );
}

function LayerPanel({ layer }) {
  const [open, setOpen] = useState(true);
  const [activeNode, setActiveNode] = useState(null);
  const selected = activeNode !== null ? layer.nodes[activeNode] : null;

  return (
    <div className="layer" style={{ background: layer.headerBg }}>
      <div className="layer-header" onClick={() => setOpen(!open)}>
        <span className="layer-num">{layer.num}</span>
        <span className="layer-label">{layer.label}</span>
        <span className="layer-badge" style={{ color: layer.badgeColor, background: layer.badgeBg }}>
          {layer.badge}
        </span>
        <span className={`layer-chevron ${open ? "open" : ""}`}>▼</span>
      </div>
      {open && (
        <div className="layer-body">
          <div className="node-grid">
            {layer.nodes.map((node, i) => (
              <Node key={i} node={node} isActive={activeNode === i}
                onClick={() => setActiveNode(activeNode === i ? null : i)} />
            ))}
          </div>
          {selected && (
            <div className="detail">
              <div className="detail-title" style={{ color: selected.color }}>
                {selected.icon} {selected.name}
              </div>
              <div className="detail-body">{selected.detail}</div>
              <div className="detail-row">
                <div>
                  <div className="detail-col-title">Why this choice</div>
                  <div className="detail-body">{selected.why}</div>
                </div>
                <div>
                  <div className="detail-col-title">Trade-off</div>
                  <div className="detail-body">{selected.tradeoff}</div>
                </div>
              </div>
              <div style={{ marginTop: 12 }}>
                <div className="detail-col-title">Specs</div>
                {selected.specs.map((s, i) => <div key={i} className="detail-item mono">{s}</div>)}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function FlowView() {
  const steps = [
    { box: "User clicks link", label: "browser" },
    { box: "CloudFront Edge", label: "~4ms" },
    { box: "Cache hit?", label: "check" },
    { box: "Redirect Service", label: "on miss" },
    { box: "Redis lookup", label: "<1ms" },
    { box: "HTTP 302", label: "response" },
    { box: "Click → Kafka", label: "async" },
    { box: "Analytics DB", label: "~30s lag" },
  ];
  return (
    <div>
      <div style={{ fontSize: 13, color: T.textMuted, marginBottom: 20 }}>
        The critical redirect path — every millisecond counts. This is what happens in the 10ms between a user clicking a short link and their browser loading the destination.
      </div>
      <div className="flow">
        {steps.map((s, i) => (
          <div key={i} style={{ display: "flex", alignItems: "center" }}>
            <div>
              <div className="flow-box" style={{ borderColor: i === 0 ? T.accent : i === steps.length - 1 ? T.orange : T.border }}>
                {s.box}
              </div>
              <span className="flow-label">{s.label}</span>
            </div>
            {i < steps.length - 1 && <span className="flow-arrow">→</span>}
          </div>
        ))}
      </div>
      <div className="detail" style={{ marginTop: 0 }}>
        <div className="detail-title" style={{ color: T.green }}>⚡ Why the redirect is so fast</div>
        <div className="detail-body">
          CloudFront caches warm links at the edge — no origin hit. On a miss, Redis answers in under 1ms.
          The click event is emitted to Kafka asynchronously — the redirect service does not wait for analytics.
          Total user-perceived latency: 4ms (cached) to 12ms (cold miss). PostgreSQL is never in the redirect path.
        </div>
      </div>
    </div>
  );
}

function DecisionsView() {
  return (
    <div>
      <div style={{ fontSize: 13, color: T.textMuted, marginBottom: 16 }}>
        Every architecture is a set of trade-offs. These are the six hardest decisions and the reasoning behind each.
      </div>
      <table className="decision-table">
        <thead>
          <tr>
            <th>Decision</th>
            <th>Chosen</th>
            <th>Why</th>
            <th>Risk / Trade-off</th>
          </tr>
        </thead>
        <tbody>
          {DECISIONS.map((d, i) => (
            <tr key={i}>
              <td style={{ color: T.text, fontWeight: 500 }}>{d.decision}</td>
              <td><span className="pill" style={{ background: T.accentGlow, color: T.accent }}>{d.chosen}</span></td>
              <td>{d.why}</td>
              <td style={{ color: T.orange }}>{d.risk}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SLOView() {
  return (
    <div>
      <div style={{ fontSize: 13, color: T.textMuted, marginBottom: 4 }}>
        Service Level Objectives — the contract with your users. These numbers drive every infrastructure decision above.
      </div>
      <div className="slo-grid">
        {SLOs.map((s, i) => (
          <div key={i} className="slo-card">
            <div className="slo-val" style={{ color: s.color }}>{s.val}</div>
            <div className="slo-label">{s.label}</div>
          </div>
        ))}
      </div>
      <div className="detail" style={{ marginTop: 12 }}>
        <div className="detail-title" style={{ color: T.accent }}>📐 How SLOs drive decisions</div>
        <div className="detail-body">
          The 10ms redirect P99 is why Redis sits in the hot path and PostgreSQL does not.
          The 99.99% uptime (52 min downtime/year) is why every layer is Multi-AZ.
          The 30s analytics lag is why Kafka decoupling is acceptable — real-time analytics would require ClickHouse or Flink and 3× the cost.
        </div>
      </div>
      <div className="code">{INFRA_CODE}</div>
    </div>
  );
}

// ─── ROOT ─────────────────────────────────────────────────────────────────────
export default function App() {
  const [view, setView] = useState("layers");
  const views = [
    { id: "layers", label: "🏗 All Layers" },
    { id: "flow", label: "⚡ Redirect Flow" },
    { id: "decisions", label: "🎯 Key Decisions" },
    { id: "slo", label: "📐 SLOs & Infra" },
  ];

  return (
    <div className="root">
      <style>{CSS}</style>
      <div className="header">
        <div className="header-eye">// production architecture</div>
        <div className="header-title">URL Shortener — System Design</div>
        <div className="header-sub">Click any component to see the why, the trade-off, and the specs</div>
      </div>

      <div className="view-nav">
        {views.map(v => (
          <button key={v.id} className={`view-pill ${view === v.id ? "active" : ""}`} onClick={() => setView(v.id)}>
            {v.label}
          </button>
        ))}
      </div>

      {view === "layers" && LAYERS.map(layer => <LayerPanel key={layer.id} layer={layer} />)}
      {view === "flow" && <div className="layer"><div className="layer-body"><FlowView /></div></div>}
      {view === "decisions" && <div className="layer"><div className="layer-body"><DecisionsView /></div></div>}
      {view === "slo" && <div className="layer"><div className="layer-body"><SLOView /></div></div>}
    </div>
  );
}
