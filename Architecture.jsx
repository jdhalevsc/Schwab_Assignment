import React from "react";

const COLORS = {
  bg: "#07111f",
  panel: "#0d1b2d",
  panelAlt: "#102238",
  border: "#243951",
  text: "#eef5ff",
  muted: "#9cb0c8",
  blue: "#56a6ff",
  green: "#48d597",
  purple: "#bd9aff",
  orange: "#ffc36a",
  red: "#ff8e8e",
};

const CSS = `
  * { box-sizing: border-box; }
  .architecture { min-height: 100vh; padding: 34px 22px 52px; background: ${COLORS.bg};
    color: ${COLORS.text}; font-family: Inter, system-ui, sans-serif; }
  .architecture-inner { max-width: 1120px; margin: 0 auto; }
  .architecture h1, .architecture h2, .architecture h3, .architecture p { margin: 0; }
  .arch-eyebrow { color: ${COLORS.blue}; font: 11px ui-monospace, monospace;
    letter-spacing: 2px; text-transform: uppercase; margin-bottom: 10px !important; }
  .arch-title { font-size: clamp(27px, 4vw, 38px); letter-spacing: -1.2px; }
  .arch-subtitle { max-width: 760px; margin-top: 9px !important; color: ${COLORS.muted};
    font-size: 14px; line-height: 1.65; }
  .arch-badges { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 16px; }
  .arch-badge { padding: 5px 10px; border: 1px solid ${COLORS.border}; border-radius: 99px;
    color: ${COLORS.muted}; font: 11px ui-monospace, monospace; }
  .arch-section { margin-top: 30px; }
  .arch-section-heading { display: flex; align-items: baseline; gap: 10px; margin-bottom: 12px; }
  .arch-section-heading h2 { font-size: 16px; }
  .arch-section-heading span { color: ${COLORS.muted}; font-size: 11px; }
  .arch-card { min-width: 0; padding: 15px 16px; border: 1px solid ${COLORS.border};
    border-radius: 10px; background: ${COLORS.panel}; }
  .arch-card h3 { font-size: 13px; margin-bottom: 6px; }
  .arch-card p { color: ${COLORS.muted}; font-size: 11px; line-height: 1.6; }
  .arch-kicker { margin-bottom: 6px !important; color: ${COLORS.blue} !important;
    font: 10px ui-monospace, monospace !important; letter-spacing: .7px; text-transform: uppercase; }
  .arch-source { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; }
  .arch-source .arch-card { text-align: center; }
  .arch-arrow { align-self: center; color: ${COLORS.blue}; font-size: 20px; text-align: center; }
  .arch-flow { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 9px; }
  .arch-flow-step { position: relative; min-height: 92px; padding: 13px 14px;
    border: 1px solid ${COLORS.border}; border-radius: 9px; background: ${COLORS.panel}; }
  .arch-flow-step:not(:nth-child(4n))::after { content: "→"; position: absolute; z-index: 1;
    top: 29px; right: -15px; color: ${COLORS.muted}; font-size: 18px; }
  .arch-step-number { display: block; margin-bottom: 7px; color: ${COLORS.blue};
    font: 10px ui-monospace, monospace; }
  .arch-flow-step strong { display: block; margin-bottom: 4px; font-size: 11px; }
  .arch-flow-step small { display: block; color: ${COLORS.muted}; font-size: 10px; line-height: 1.5; }
  .arch-grid-2 { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
  .arch-grid-3 { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; }
  .arch-card-list { display: grid; gap: 8px; }
  .arch-row { display: grid; grid-template-columns: 130px 1fr; gap: 10px;
    padding-top: 8px; border-top: 1px solid ${COLORS.border}; }
  .arch-row:first-child { padding-top: 0; border-top: 0; }
  .arch-row strong { color: ${COLORS.text}; font-size: 11px; }
  .arch-row span { color: ${COLORS.muted}; font-size: 10px; line-height: 1.5; }
  .arch-callout { margin-top: 12px; padding: 13px 15px; border: 1px solid rgba(255,195,106,.34);
    border-radius: 9px; background: rgba(255,195,106,.07); color: ${COLORS.orange};
    font-size: 11px; line-height: 1.65; }
  .arch-callout strong { color: ${COLORS.text}; }
  .arch-boundary { border-color: rgba(255,142,142,.32); background: rgba(255,142,142,.06); }
  .arch-boundary .arch-kicker { color: ${COLORS.red} !important; }
  .arch-tag { display: inline-block; margin: 3px 4px 0 0; padding: 3px 7px;
    border: 1px solid ${COLORS.border}; border-radius: 5px; color: ${COLORS.muted};
    font: 9px ui-monospace, monospace; }
  .arch-muted { color: ${COLORS.muted}; }
  @media (max-width: 720px) {
    .arch-flow { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .arch-flow-step:not(:nth-child(4n))::after { content: none; }
    .arch-flow-step:nth-child(2n+1)::after { content: "→"; position: absolute; z-index: 1;
      top: 29px; right: -15px; color: ${COLORS.muted}; font-size: 18px; }
    .arch-grid-3 { grid-template-columns: 1fr; }
  }
  @media (max-width: 520px) {
    .architecture { padding: 24px 14px 40px; }
    .arch-grid-2, .arch-source { grid-template-columns: 1fr; }
    .arch-arrow { transform: rotate(90deg); }
    .arch-row { grid-template-columns: 1fr; gap: 4px; }
  }
`;

function FlowStep({ number, title, description }) {
  return (
    <div className="arch-flow-step">
      <span className="arch-step-number">{number}</span>
      <strong>{title}</strong>
      <small>{description}</small>
    </div>
  );
}

function Card({ title, kicker, children, className = "" }) {
  return (
    <section className={`arch-card ${className}`}>
      {kicker && <p className="arch-kicker">{kicker}</p>}
      <h3>{title}</h3>
      {children}
    </section>
  );
}

export default function Architecture() {
  return (
    <main className="architecture">
      <style>{CSS}</style>
      <div className="architecture-inner">
        <header>
          <p className="arch-eyebrow">SchwabAssignment · implementation view</p>
          <h1 className="arch-title">URL Shortener Architecture</h1>
          <p className="arch-subtitle">
            This diagram follows the code in <code>App.jsx</code>: a React single-page
            application with module-scoped in-memory services. It describes the running
            browser demo, not a deployed backend.
          </p>
          <div className="arch-badges">
            <span className="arch-badge">React 18</span>
            <span className="arch-badge">Vite</span>
            <span className="arch-badge">Browser runtime</span>
            <span className="arch-badge">No backend required</span>
          </div>
        </header>

        <section className="arch-section" aria-labelledby="entry-heading">
          <div className="arch-section-heading">
            <h2 id="entry-heading">Application entry</h2>
            <span>static page bootstraps the React app</span>
          </div>
          <div className="arch-source">
            <Card title="index.html" kicker="Document">Root element + Vite module entry.</Card>
            <div className="arch-arrow" aria-hidden="true">→</div>
            <Card title="src/main.jsx" kicker="Bootstrap">Creates the React root and renders <code>App</code>.</Card>
            <div className="arch-arrow" aria-hidden="true">→</div>
            <Card title="App.jsx" kicker="Single application module">Navigation, views, stateful UI, domain logic, and browser adapters.</Card>
          </div>
        </section>

        <section className="arch-section" aria-labelledby="ui-heading">
          <div className="arch-section-heading">
            <h2 id="ui-heading">UI and application services</h2>
            <span>all implemented in the browser in App.jsx</span>
          </div>
          <div className="arch-grid-3">
            <Card title="App shell + views" kicker="React UI">
              <p>Tab navigation selects Shorten, Links, Analytics, Integrations, Scenarios,
                Tests, Engineering Log, Health, or API. Chatbot floats across views.</p>
            </Card>
            <Card title="ValidationGate + RateLimiter" kicker="Input controls">
              <p>Validates URL protocol/host/length, aliases, tags, and title; applies an
                in-memory sliding-window limit before link creation.</p>
            </Card>
            <Card title="URLStore + AuditLog" kicker="Domain state">
              <p>Map of links, click-event array, and append-only audit array. Seed links
                and synthetic analytics are created at startup.</p>
            </Card>
            <Card title="Analytics + TestRunner" kicker="Local services">
              <p>Analytics aggregate stored click events in memory. The custom test
                harness runs the built-in suites in the Tests view.</p>
            </Card>
            <Card title="AI engine" kicker="Anthropic API">
              <p>Summaries, alias suggestions, anomaly analysis, and chatbot replies call
                Claude through browser <code>fetch</code>.</p>
            </Card>
            <Card title="Integration adapters" kicker="Mock by default">
              <p>VirusTotal, Safe Browsing, Slack, and compliance webhook adapters use
                simulated responses while <code>MOCK_MODE</code> is true.</p>
            </Card>
          </div>
        </section>

        <section className="arch-section" aria-labelledby="create-heading">
          <div className="arch-section-heading">
            <h2 id="create-heading">Create-short-link flow</h2>
            <span>Shorten view</span>
          </div>
          <div className="arch-flow">
            <FlowStep number="01 · INPUT" title="ShortenView" description="URL, optional alias, expiry, tags, and title." />
            <FlowStep number="02 · GUARD" title="ValidationGate" description="Validate fields; reject invalid or reserved values." />
            <FlowStep number="03 · LIMIT" title="RateLimiter" description="Sliding window: 10 creation attempts per minute." />
            <FlowStep number="04 · SAFETY" title="URL safety checks" description="VirusTotal + Safe Browsing run in parallel." />
            <FlowStep number="05 · WRITE" title="URLStore.create" description="Generate crypto-random code or accept a validated alias." />
            <FlowStep number="06 · RECORD" title="AuditLog" description="Append CREATE event; update the in-memory store." />
            <FlowStep number="07 · NOTIFY" title="Compliance webhook" description="Send LINK_CREATED asynchronously; simulated by default." />
            <FlowStep number="AI · OPTIONAL" title="Claude assistance" description="Summarize URL and suggest aliases before submit." />
          </div>
          <div className="arch-callout">
            <strong>Safety behavior:</strong> a confirmed unsafe result blocks creation.
            Integration errors are treated as safe with a warning (fail-open); when
            <code> MOCK_MODE </code> is enabled, the safety providers are simulated.
          </div>
        </section>

        <section className="arch-section" aria-labelledby="click-heading">
          <div className="arch-section-heading">
            <h2 id="click-heading">Click simulation and analytics</h2>
            <span>Links and Analytics views</span>
          </div>
          <div className="arch-grid-2">
            <Card title="Simulated link click" kicker="LinksView → URLStore.click">
              <div className="arch-card-list">
                <div className="arch-row"><strong>Lookup + expiry</strong><span>Find code; lazily remove expired links on access.</span></div>
                <div className="arch-row"><strong>Record activity</strong><span>Increment count, append synthetic referrer/country/user-agent data, and audit CLICK.</span></div>
                <div className="arch-row"><strong>Refresh UI</strong><span>Links view refreshes its local state and shows the updated count.</span></div>
              </div>
            </Card>
            <Card title="Analytics and anomaly review" kicker="AnalyticsView">
              <div className="arch-card-list">
                <div className="arch-row"><strong>Local aggregation</strong><span>URLStore computes totals by referrer, country, day, user agent, and hour.</span></div>
                <div className="arch-row"><strong>AI analysis</strong><span>Claude analyzes link summaries and local analytics on request.</span></div>
                <div className="arch-row"><strong>Alerts</strong><span>Medium/high anomalies trigger Slack and compliance adapters (mocked by default).</span></div>
              </div>
            </Card>
          </div>
          <div className="arch-callout arch-boundary">
            <strong>Important:</strong> the “Simulate click” action calls a local store method.
            This prototype does not expose a real <code>go.schwab.com/:code</code> redirect
            endpoint and does not send an HTTP 302 response.
          </div>
        </section>

        <section className="arch-section" aria-labelledby="state-heading">
          <div className="arch-section-heading">
            <h2 id="state-heading">Runtime state and external boundaries</h2>
            <span>what persists, and what leaves the browser</span>
          </div>
          <div className="arch-grid-2">
            <Card title="Module-scoped in-memory state" kicker="Resets on reload">
              <p><span className="arch-tag">URLStore Map + click array</span>
                <span className="arch-tag">AuditLog array</span>
                <span className="arch-tag">RateLimiter timestamps</span></p>
              <p style={{ marginTop: 9 }}>No database, localStorage persistence, or server-side
                store is wired into this app. The initial dataset is seeded when the module loads.</p>
            </Card>
            <Card title="Outbound network calls" kicker="Browser fetch">
              <p><span className="arch-tag">Anthropic Messages API</span>
                <span className="arch-tag">Safety providers*</span>
                <span className="arch-tag">Slack*</span>
                <span className="arch-tag">Compliance webhook*</span></p>
              <p style={{ marginTop: 9 }}>*These integration adapters return mock responses
                while <code>MOCK_MODE</code> is enabled. Claude AI calls are live network
                requests, not part of that mock switch.</p>
            </Card>
          </div>
        </section>

        <section className="arch-section">
          <Card title="Not part of this running prototype" kicker="Production target is separate">
            <p>API Gateway, authentication service, CloudFront caching, Redis, PostgreSQL,
              Kafka, S3, and a deployed redirect service are not connected to App.jsx.
              They may be considered for a production implementation, but are not shown
              here as active runtime components.</p>
          </Card>
        </section>
      </div>
    </main>
  );
}
