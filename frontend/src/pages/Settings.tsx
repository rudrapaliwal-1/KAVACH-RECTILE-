import { useEffect, useState } from "react";
import { RefreshCw, Server, Database, Bot, Container, ShieldAlert, CheckCircle2, XCircle, AlertTriangle, KeyRound, Wrench, Compass } from "lucide-react";
import { apiBaseUrl, request } from "../api/client";
import type { ReadinessCheck, ReadinessResponse } from "../api/types";

type AiReady = { configured: boolean; source_sharing: string; status: string };
type Observability = { configured: boolean; hosted_delivery_verified: boolean; local_workflow_events: boolean };

export default function Settings() {
  const [me, setMe] = useState<{ user: { email: string } } | null>(null);
  const [ai, setAi] = useState<AiReady | null>(null);
  const [obs, setObs] = useState<Observability | null>(null);
  const [ready, setReady] = useState<ReadinessResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function refresh() {
    setLoading(true);
    setError("");
    try {
      const [identity, provider, telemetry, health] = await Promise.all([
        request<{ user: { email: string } }>("/api/auth/me").catch(() => null),
        request<AiReady>("/api/ai/readiness").catch(() => null),
        request<Observability>("/api/observability/status").catch(() => null),
        request<ReadinessResponse>("/ready").catch(err => {
          if (err && typeof err === "object" && "payload" in err && err.payload) {
            return err.payload as ReadinessResponse;
          }
          return { status: "not_ready", checks: {} } as ReadinessResponse;
        }),
      ]);
      setMe(identity);
      setAi(provider);
      setObs(telemetry);
      setReady(health);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load settings");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  const checks = ready?.checks || {};

  function renderCheckRow(label: string, check?: ReadinessCheck) {
    const isReady = check?.status === "ready";
    return (
      <div
        key={label}
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-start",
          padding: "10px 0",
          borderBottom: "1px solid rgba(255,255,255,0.06)",
          gap: 12,
        }}
      >
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 6, fontWeight: 500 }}>
            {isReady ? <CheckCircle2 size={15} style={{ color: "#4ade80" }} /> : <XCircle size={15} style={{ color: "#f87171" }} />}
            <span>{label}</span>
          </div>
          {check && check.action && check.action !== "none" && (
            <div style={{ fontSize: "0.8rem", color: "var(--text-muted, #99a)", marginTop: 2, marginLeft: 21 }}>
              Action: <code>{check.action}</code>
            </div>
          )}
        </div>
        <span
          style={{
            padding: "2px 8px",
            borderRadius: 4,
            fontSize: "0.75rem",
            fontWeight: 600,
            background: isReady ? "rgba(34,197,94,0.15)" : "rgba(239,68,68,0.15)",
            color: isReady ? "#4ade80" : "#f87171",
            textTransform: "uppercase",
          }}
        >
          {check?.status || "UNKNOWN"}
        </span>
      </div>
    );
  }

  return (
    <div className="page">
      <div className="page-heading">
        <div>
          <div className="eyebrow">ENVIRONMENT & DIAGNOSTICS</div>
          <h1>Settings & Readiness</h1>
          <p>Readiness diagnostics for API, database, AI model provider, and Docker verifier dependencies with actionable messages.</p>
        </div>
        <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
          <button
            className="button button-secondary"
            onClick={() => window.dispatchEvent(new CustomEvent("kavach:reboot"))}
            title="Replay initialization sequence"
          >
            <Compass size={15} /> Replay Init Sequence
          </button>
          <button className="button button-secondary" onClick={() => void refresh()} disabled={loading}>
            <RefreshCw size={15} className={loading ? "spin" : ""} /> Refresh Diagnostics
          </button>
        </div>
      </div>

      {error && <div className="error-banner" role="alert">{error}</div>}

      {/* Global Readiness Status Header */}
      <div
        className="panel"
        style={{
          padding: 16,
          marginBottom: 20,
          background: ready?.status === "ready" ? "rgba(34,197,94,0.08)" : "rgba(245,158,11,0.08)",
          border: `1px solid ${ready?.status === "ready" ? "rgba(34,197,94,0.25)" : "rgba(245,158,11,0.25)"}`,
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            {ready?.status === "ready" ? (
              <CheckCircle2 size={24} style={{ color: "#4ade80" }} />
            ) : (
              <AlertTriangle size={24} style={{ color: "#f59e0b" }} />
            )}
            <div>
              <h3 style={{ margin: 0, fontSize: "1.1rem" }}>
                Overall System Readiness: {ready?.status === "ready" ? "READY FOR AUTONOMOUS OPERATION" : "DEGRADED / NOT READY"}
              </h3>
              <p style={{ margin: "2px 0 0", fontSize: "0.85rem", color: "var(--text-muted, #889)" }}>
                {ready?.status === "ready"
                  ? "All core dependencies (API, Database, Model Provider, Docker Verifier) are reachable."
                  : "One or more dependencies require attention. Review actionable resolution instructions below."}
              </p>
            </div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: "0.85rem", color: "var(--text-muted, #889)" }}>
            <KeyRound size={14} /> Zero Secrets Exposed (Tokens kept in memory only)
          </div>
        </div>
      </div>

      {loading ? (
        <div className="loading-state">
          <RefreshCw size={18} className="spin" /> Probing local and background dependencies…
        </div>
      ) : (
        <div className="dashboard-grid">
          {/* Database & API Core */}
          <section className="panel" style={{ padding: 20 }}>
            <div className="panel-heading" style={{ marginBottom: 10 }}>
              <div>
                <div className="eyebrow">PERSISTENCE & SERVICE</div>
                <h2><Database size={17} /> API & Database Core</h2>
              </div>
              <Server size={17} className="text-cyan" />
            </div>
            <p style={{ fontSize: "0.85rem", color: "var(--text-muted, #889)", marginBottom: 12 }}>
              API Base: <code>{apiBaseUrl}</code>
            </p>
            {renderCheckRow("SQLite Database", checks.database)}
            {renderCheckRow("Workspace Paths", checks.configuration)}
            {renderCheckRow("System Patch Utility", checks.patch_utility)}
          </section>

          {/* AI Model Provider */}
          <section className="panel" style={{ padding: 20 }}>
            <div className="panel-heading" style={{ marginBottom: 10 }}>
              <div>
                <div className="eyebrow">REMEDIATION ENGINE</div>
                <h2><Bot size={17} /> AI Model Provider</h2>
              </div>
              <Bot size={17} className="text-cyan" />
            </div>
            <p style={{ fontSize: "0.85rem", color: "var(--text-muted, #889)", marginBottom: 12 }}>
              Configured Model: <code>qwen2.5-coder:7b</code> via local Ollama
            </p>
            {renderCheckRow("Ollama HTTP Daemon", checks.ollama)}
            {renderCheckRow("Target Model Installed", checks.model)}
            {renderCheckRow("Agent Proposal Callable", checks.agent_callable)}
            {ai && (
              <p style={{ fontSize: "0.8rem", color: "var(--text-secondary, #ccc)", marginTop: 8 }}>
                Advisory AI Analysis: <strong>{ai.status}</strong> ({ai.source_sharing || "Explicit source-sharing consent required"}).
              </p>
            )}
          </section>

          {/* Independent Docker Verifier */}
          <section className="panel" style={{ padding: 20 }}>
            <div className="panel-heading" style={{ marginBottom: 10 }}>
              <div>
                <div className="eyebrow">INDEPENDENT VERIFICATION</div>
                <h2><Container size={17} /> Isolated Docker Verifier</h2>
              </div>
              <Container size={17} className="text-cyan" />
            </div>
            <p style={{ fontSize: "0.85rem", color: "var(--text-muted, #889)", marginBottom: 12 }}>
              Restricted execution environment: <code>sentinel-verification-lab:latest</code>
            </p>
            {renderCheckRow("Docker Host Daemon", checks.docker)}
            {renderCheckRow("Verifier Lab Image", checks.verifier_image)}
            {renderCheckRow("Verifier Adapter Callable", checks.verifier_callable)}
          </section>

          {/* Account & Session Security */}
          <section className="panel" style={{ padding: 20 }}>
            <div className="panel-heading" style={{ marginBottom: 10 }}>
              <div>
                <div className="eyebrow">AUTHENTICATION</div>
                <h2><ShieldAlert size={17} /> Account & Observability</h2>
              </div>
              <KeyRound size={17} className="text-cyan" />
            </div>
            <p style={{ fontSize: "0.85rem", marginBottom: 8 }}>
              Active Principal: <strong>{me?.user.email || "Local Operator Session"}</strong>
            </p>
            <div style={{ margin: "8px 0 12px", fontSize: "0.82rem", color: "var(--text-muted, #889)" }}>
              <div>Neatlogs Telemetry: <strong>{obs?.configured ? "Configured" : "Not configured (Local events active)"}</strong></div>
              <div>Hosted Delivery Verified: {obs?.hosted_delivery_verified ? "Yes" : "No"}</div>
            </div>
            <p style={{ fontSize: "0.85rem", color: "var(--text-muted, #889)", marginBottom: 12 }}>
              CSRF protection is active. Credentials and tokens are held in session memory only and never written to storage.
            </p>
            <div style={{ display: "flex", gap: 10, marginTop: 16 }}>
              <button
                className="button button-secondary"
                onClick={() => window.dispatchEvent(new Event("sentinel-disconnect"))}
              >
                Log Out
              </button>
            </div>
          </section>
        </div>
      )}

      {/* Actionable Dependency Setup Runbook Card */}
      <section className="panel" style={{ padding: 20, marginTop: 20 }}>
        <div className="panel-heading" style={{ marginBottom: 8 }}>
          <div>
            <div className="eyebrow">QUICK RESOLUTION</div>
            <h2><Wrench size={18} /> Dependency Setup Commands</h2>
          </div>
        </div>
        <p style={{ fontSize: "0.85rem", color: "var(--text-muted, #889)", marginBottom: 12 }}>
          If any dependency reports <code>unavailable</code> above, execute the corresponding documented command:
        </p>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: 12 }}>
          <div style={{ background: "rgba(0,0,0,0.25)", padding: 12, borderRadius: 6 }}>
            <strong>1. Build Isolated Verifier Docker Image</strong>
            <pre style={{ margin: "6px 0 0", fontSize: "0.8rem", whiteSpace: "pre-wrap" }}>
              docker build -t sentinel-verification-lab:latest -f verification/Dockerfile verification/
            </pre>
          </div>
          <div style={{ background: "rgba(0,0,0,0.25)", padding: 12, borderRadius: 6 }}>
            <strong>2. Install Remediation Model in Ollama</strong>
            <pre style={{ margin: "6px 0 0", fontSize: "0.8rem", whiteSpace: "pre-wrap" }}>
              ollama pull qwen2.5-coder:7b
            </pre>
          </div>
          <div style={{ background: "rgba(0,0,0,0.25)", padding: 12, borderRadius: 6 }}>
            <strong>3. Start Docker Desktop (Windows)</strong>
            <pre style={{ margin: "6px 0 0", fontSize: "0.8rem", whiteSpace: "pre-wrap" }}>
              Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe"
            </pre>
          </div>
        </div>
      </section>
    </div>
  );
}
