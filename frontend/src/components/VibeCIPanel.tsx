import { useEffect, useState } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RefreshCw,
  Zap,
  Play,
  Layers,
  FileCheck2,
  Bot,
  Info,
} from "lucide-react";
import { vibeciApi, type VibeCIVerifyPayload } from "../api/vibeci";
import type { VibeCIReport, VibeCIStatus } from "../api/types";
import { request } from "../api/client";

interface ProjectOption {
  id: string;
  name: string;
  status: string;
}

export default function VibeCIPanel() {
  const [status, setStatus] = useState<VibeCIStatus | null>(null);
  const [projects, setProjects] = useState<ProjectOption[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<string>("");
  const [report, setReport] = useState<VibeCIReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [expandedCheck, setExpandedCheck] = useState<string | null>(null);

  // Options
  const [runBuild, setRunBuild] = useState(false);
  const [runTests, setRunTests] = useState(true);
  const [runSmoke, setRunSmoke] = useState(false);
  const [changedOnly, setChangedOnly] = useState(false);

  // Rules
  const [rules, setRules] = useState<Record<string, { configured: boolean; path: string }> | null>(null);
  const [ruleMessage, setRuleMessage] = useState("");

  useEffect(() => {
    void loadInitialData();
  }, []);

  useEffect(() => {
    if (selectedProjectId) {
      void loadProjectReports(selectedProjectId);
      void loadProjectRules(selectedProjectId);
    }
  }, [selectedProjectId]);

  async function loadInitialData() {
    try {
      const s = await vibeciApi.getStatus();
      setStatus(s);
    } catch {
      setStatus(null);
    }

    try {
      const projs = await request<ProjectOption[]>("/api/projects");
      setProjects(projs);
      if (projs.length > 0 && !selectedProjectId) {
        setSelectedProjectId(projs[0].id);
      }
    } catch {
      // ignore
    }
  }

  async function loadProjectReports(projectId: string) {
    try {
      const reports = await vibeciApi.listReports(projectId);
      if (reports.length > 0) {
        const full = await vibeciApi.getReport(projectId, reports[0].id);
        setReport(full.report);
      } else {
        setReport(null);
      }
    } catch {
      setReport(null);
    }
  }

  async function loadProjectRules(projectId: string) {
    try {
      const r = await vibeciApi.getRules(projectId);
      setRules(r);
    } catch {
      setRules(null);
    }
  }

  async function handlePreflight() {
    if (!selectedProjectId) return;
    setLoading(true);
    setError("");
    try {
      const res = await vibeciApi.runPreflight(selectedProjectId);
      setReport(res);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Preflight failed");
    } finally {
      setLoading(false);
    }
  }

  async function handleVerify() {
    if (!selectedProjectId) return;
    setLoading(true);
    setError("");
    const payload: VibeCIVerifyPayload = {
      run_static: true,
      run_build: runBuild,
      run_tests: runTests,
      run_smoke: runSmoke,
      changed_only: changedOnly,
    };
    try {
      const res = await vibeciApi.runVerification(selectedProjectId, payload);
      setReport(res);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Verification execution failed");
    } finally {
      setLoading(false);
    }
  }

  async function handleInstallRules() {
    if (!selectedProjectId) return;
    try {
      const res = await vibeciApi.installRules(selectedProjectId, "all");
      setRuleMessage(`Installed rules: ${res.installed_files.join(", ")}`);
      void loadProjectRules(selectedProjectId);
    } catch (e) {
      setRuleMessage(e instanceof Error ? e.message : "Failed installing rules");
    }
  }

  const statusColor = (st: string) => {
    switch (st) {
      case "passed":
        return "var(--signal-lime)";
      case "failed":
      case "error":
        return "var(--threat-coral)";
      case "warning":
      case "warnings":
        return "#fbbf24";
      default:
        return "var(--lavender-muted)";
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
      {/* Engine Status & Target Project Header */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: 12,
          padding: "14px 18px",
          background: "rgba(22, 16, 36, 0.75)",
          borderRadius: 8,
          border: "1px solid rgba(183, 243, 107, 0.25)",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div
            style={{
              width: 36,
              height: 36,
              borderRadius: 8,
              background: "rgba(183, 243, 107, 0.15)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              color: "var(--signal-lime)",
            }}
          >
            <Zap size={20} />
          </div>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <strong style={{ fontSize: 15, color: "#fff" }}>VibeCI Local Verification Engine</strong>
              <span
                style={{
                  fontSize: 11,
                  padding: "2px 6px",
                  borderRadius: 4,
                  background: status?.available ? "rgba(183, 243, 107, 0.2)" : "rgba(255, 122, 112, 0.2)",
                  color: status?.available ? "var(--signal-lime)" : "var(--threat-coral)",
                  fontFamily: "monospace",
                }}
              >
                v{status?.version || "0.3.0"} • {status?.available ? "ONLINE" : "UNAVAILABLE"}
              </span>
            </div>
            <div style={{ fontSize: 12, color: "var(--lavender-muted)", marginTop: 2 }}>
              Fast pre-flight audits, secret scanning, environment check, and multi-layer verification.
            </div>
          </div>
        </div>

        {/* Project Selector & Actions */}
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <select
            value={selectedProjectId}
            onChange={e => setSelectedProjectId(e.target.value)}
            style={{
              padding: "7px 12px",
              borderRadius: 6,
              background: "rgba(33, 24, 52, 0.9)",
              border: "1px solid rgba(255,255,255,0.15)",
              color: "#fff",
              fontSize: 13,
            }}
          >
            {projects.length === 0 && <option value="">No projects available</option>}
            {projects.map(p => (
              <option key={p.id} value={p.id}>
                {p.name} ({p.id.slice(0, 16)}...)
              </option>
            ))}
          </select>

          <button
            onClick={() => void handlePreflight()}
            disabled={loading || !selectedProjectId}
            className="button button-lime"
            style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13, padding: "7px 14px" }}
          >
            {loading ? <RefreshCw size={14} className="spin" /> : <ShieldCheck size={14} />}
            Run Preflight
          </button>

          <button
            onClick={() => void handleVerify()}
            disabled={loading || !selectedProjectId}
            className="button button-ghost"
            style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13, padding: "7px 14px" }}
          >
            <Play size={14} />
            Full Verify
          </button>
        </div>
      </div>

      {/* Execution Layer Toggles */}
      <div
        style={{
          display: "flex",
          gap: 16,
          flexWrap: "wrap",
          padding: "10px 16px",
          background: "rgba(15, 10, 26, 0.5)",
          borderRadius: 6,
          fontSize: 12,
          color: "var(--lavender-muted)",
          border: "1px solid rgba(255, 255, 255, 0.05)",
        }}
      >
        <span style={{ fontWeight: 600, color: "var(--lavender)" }}>Verification Layers:</span>
        <label style={{ display: "flex", alignItems: "center", gap: 6, cursor: "pointer" }}>
          <input type="checkbox" checked disabled />
          <span>Layer 1: Static Health &amp; Preflight (Always Active)</span>
        </label>
        <label style={{ display: "flex", alignItems: "center", gap: 6, cursor: "pointer" }}>
          <input type="checkbox" checked={runBuild} onChange={e => setRunBuild(e.target.checked)} />
          <span>Layer 2: Production Build</span>
        </label>
        <label style={{ display: "flex", alignItems: "center", gap: 6, cursor: "pointer" }}>
          <input type="checkbox" checked={runTests} onChange={e => setRunTests(e.target.checked)} />
          <span>Layer 3: Existing Unit Tests</span>
        </label>
        <label style={{ display: "flex", alignItems: "center", gap: 6, cursor: "pointer" }}>
          <input type="checkbox" checked={runSmoke} onChange={e => setRunSmoke(e.target.checked)} />
          <span>Layer 4: Runtime Smoke Probe</span>
        </label>
        <label style={{ display: "flex", alignItems: "center", gap: 6, cursor: "pointer" }}>
          <input type="checkbox" checked={changedOnly} onChange={e => setChangedOnly(e.target.checked)} />
          <span>Change-Aware Diff Mode</span>
        </label>
      </div>

      {error && (
        <div style={{ padding: "10px 14px", borderRadius: 6, background: "rgba(255, 122, 112, 0.15)", border: "1px solid rgba(255, 122, 112, 0.3)", color: "var(--threat-coral)", fontSize: 13 }}>
          {error}
        </div>
      )}

      {/* Execution Results */}
      {report ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          {/* Verdict Card */}
          <div
            style={{
              padding: "16px 20px",
              borderRadius: 8,
              background: "rgba(22, 16, 36, 0.85)",
              border: `1px solid ${statusColor(report.status)}`,
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              flexWrap: "wrap",
              gap: 12,
            }}
          >
            <div>
              <div style={{ fontSize: 11, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--lavender-muted)" }}>
                VERDICT // {report.project_type.toUpperCase()} ECOSYSTEM
              </div>
              <div style={{ fontSize: 22, fontWeight: 700, color: statusColor(report.status), display: "flex", alignItems: "center", gap: 8, marginTop: 4 }}>
                {report.status === "passed" && <CheckCircle2 size={24} />}
                {report.status === "failed" && <XCircle size={24} />}
                {report.status === "warnings" && <AlertTriangle size={24} />}
                <span>VERDICT: {report.status.toUpperCase()}</span>
              </div>
              <div style={{ fontSize: 12, color: "var(--lavender-muted)", marginTop: 4 }}>
                Execution completed in <strong>{report.total_duration_ms} ms</strong> • Timestamp: {report.timestamp}
              </div>
            </div>

            {/* Counters */}
            <div style={{ display: "flex", gap: 12 }}>
              <div style={{ padding: "8px 14px", borderRadius: 6, background: "rgba(0,0,0,0.3)", textAlign: "center" }}>
                <div style={{ fontSize: 11, color: "var(--lavender-muted)" }}>PASSED</div>
                <div style={{ fontSize: 18, fontWeight: 700, color: "var(--signal-lime)" }}>{report.summary.passed}</div>
              </div>
              <div style={{ padding: "8px 14px", borderRadius: 6, background: "rgba(0,0,0,0.3)", textAlign: "center" }}>
                <div style={{ fontSize: 11, color: "var(--lavender-muted)" }}>FAILED</div>
                <div style={{ fontSize: 18, fontWeight: 700, color: report.summary.failed > 0 ? "var(--threat-coral)" : "var(--lavender-muted)" }}>
                  {report.summary.failed}
                </div>
              </div>
              <div style={{ padding: "8px 14px", borderRadius: 6, background: "rgba(0,0,0,0.3)", textAlign: "center" }}>
                <div style={{ fontSize: 11, color: "var(--lavender-muted)" }}>WARNINGS</div>
                <div style={{ fontSize: 18, fontWeight: 700, color: report.summary.warnings > 0 ? "#fbbf24" : "var(--lavender-muted)" }}>
                  {report.summary.warnings}
                </div>
              </div>
              <div style={{ padding: "8px 14px", borderRadius: 6, background: "rgba(0,0,0,0.3)", textAlign: "center" }}>
                <div style={{ fontSize: 11, color: "var(--lavender-muted)" }}>NOT CHECKED</div>
                <div style={{ fontSize: 18, fontWeight: 700, color: "var(--orbit-violet)" }}>{report.summary.not_checked}</div>
              </div>
            </div>
          </div>

          {/* What Needs Attention / Failure Breakdown */}
          {report.checks.some(c => c.status === "failed" || c.status === "warning") && (
            <div
              style={{
                padding: "16px 20px",
                borderRadius: 8,
                background: "rgba(35, 18, 30, 0.9)",
                border: "1px solid rgba(255, 122, 112, 0.35)",
              }}
            >
              <div style={{ fontSize: 13, fontWeight: 700, color: "var(--threat-coral)", display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
                <ShieldAlert size={16} />
                <span>What Needs Attention?</span>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                {report.checks
                  .filter(c => c.status === "failed" || c.status === "warning")
                  .map(c => (
                    <div
                      key={c.name}
                      style={{
                        padding: "10px 14px",
                        borderRadius: 6,
                        background: "rgba(0, 0, 0, 0.3)",
                        border: `1px solid ${c.status === "failed" ? "rgba(255, 122, 112, 0.3)" : "rgba(251, 191, 36, 0.3)"}`,
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span style={{ fontWeight: 600, fontFamily: "monospace", fontSize: 13, color: statusColor(c.status) }}>
                          [{c.status.toUpperCase()}] {c.name}
                        </span>
                        <span style={{ fontSize: 11, color: "var(--lavender-muted)", fontFamily: "monospace" }}>
                          layer: {c.layer}
                        </span>
                      </div>
                      <div style={{ fontSize: 12, color: "#fff", marginTop: 4 }}>{c.summary}</div>
                      {c.failure_details.length > 0 && (
                        <ul style={{ margin: "6px 0 0", paddingLeft: 18, fontSize: 12, color: "#fca5a5" }}>
                          {c.failure_details.map((d, i) => (
                            <li key={i}>{d}</li>
                          ))}
                        </ul>
                      )}
                      {c.file_locations.length > 0 && (
                        <div style={{ marginTop: 6, display: "flex", gap: 6, flexWrap: "wrap" }}>
                          {c.file_locations.map((loc, i) => (
                            <span
                              key={i}
                              style={{
                                fontSize: 11,
                                fontFamily: "monospace",
                                padding: "2px 6px",
                                borderRadius: 4,
                                background: "rgba(255,255,255,0.08)",
                                color: "var(--signal-lime)",
                              }}
                            >
                              {loc.file}:{loc.line || ""}{loc.column ? `:${loc.column}` : ""}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
              </div>
            </div>
          )}

          {/* Executed Checks Table */}
          <div
            style={{
              padding: "16px 20px",
              borderRadius: 8,
              background: "rgba(22, 16, 36, 0.8)",
              border: "1px solid rgba(255, 255, 255, 0.08)",
            }}
          >
            <div style={{ fontSize: 13, fontWeight: 700, color: "#fff", marginBottom: 12, display: "flex", alignItems: "center", gap: 8 }}>
              <Layers size={16} color="var(--signal-lime)" />
              <span>Executed Verification Checks ({report.checks.length})</span>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Status</th>
                    <th>Check Name</th>
                    <th>Layer</th>
                    <th>Duration</th>
                    <th>Summary</th>
                    <th>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {report.checks.map(c => {
                    const isExpanded = expandedCheck === c.name;
                    return (
                      <>
                        <tr key={c.name}>
                          <td>
                            <span
                              style={{
                                display: "inline-flex",
                                alignItems: "center",
                                gap: 4,
                                fontSize: 11,
                                fontWeight: 600,
                                padding: "2px 8px",
                                borderRadius: 4,
                                background: `rgba(${c.status === "passed" ? "183, 243, 107" : c.status === "warning" ? "251, 191, 36" : "255, 122, 112"}, 0.15)`,
                                color: statusColor(c.status),
                                textTransform: "uppercase",
                              }}
                            >
                              {c.status}
                            </span>
                          </td>
                          <td>
                            <code style={{ fontSize: 12 }}>{c.name}</code>
                          </td>
                          <td>
                            <span style={{ fontSize: 11, color: "var(--lavender-muted)" }}>{c.layer}</span>
                          </td>
                          <td>
                            <span style={{ fontSize: 11, fontFamily: "monospace" }}>{c.duration_ms} ms</span>
                          </td>
                          <td style={{ maxWidth: 350 }}>
                            <span style={{ fontSize: 12 }}>{c.summary}</span>
                          </td>
                          <td>
                            {(c.stdout || c.stderr || c.failure_details.length > 0) && (
                              <button
                                className="button button-ghost-sm"
                                onClick={() => setExpandedCheck(isExpanded ? null : c.name)}
                                style={{ padding: "2px 8px", fontSize: 11 }}
                              >
                                {isExpanded ? "Hide" : "Inspect"}
                              </button>
                            )}
                          </td>
                        </tr>
                        {isExpanded && (
                          <tr key={`${c.name}-exp`}>
                            <td colSpan={6} style={{ background: "rgba(10, 8, 18, 0.9)", padding: 14 }}>
                              <div style={{ fontSize: 11, fontFamily: "monospace", color: "var(--lavender-muted)", marginBottom: 6 }}>
                                Command: {c.command} {c.exit_code !== null ? `(exit code: ${c.exit_code})` : ""}
                              </div>
                              {c.stdout && (
                                <div style={{ marginBottom: 8 }}>
                                  <div style={{ fontSize: 11, color: "var(--lavender-muted)" }}>STDOUT:</div>
                                  <pre style={{ background: "rgba(0,0,0,0.5)", padding: 8, borderRadius: 4, fontSize: 11, color: "var(--cream-soft)", maxHeight: 160, overflowY: "auto" }}>
                                    {c.stdout}
                                  </pre>
                                </div>
                              )}
                              {c.stderr && (
                                <div>
                                  <div style={{ fontSize: 11, color: "var(--threat-coral)" }}>STDERR:</div>
                                  <pre style={{ background: "rgba(0,0,0,0.5)", padding: 8, borderRadius: 4, fontSize: 11, color: "#fca5a5", maxHeight: 160, overflowY: "auto" }}>
                                    {c.stderr}
                                  </pre>
                                </div>
                              )}
                            </td>
                          </tr>
                        )}
                      </>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* Honest Accounting: Unverified Capabilities */}
          {report.unverified_capabilities.length > 0 && (
            <div
              style={{
                padding: "16px 20px",
                borderRadius: 8,
                background: "rgba(23, 16, 37, 0.7)",
                border: "1px solid rgba(139, 124, 255, 0.3)",
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, fontWeight: 700, color: "var(--lavender)" }}>
                  <Info size={16} color="var(--orbit-violet)" />
                  <span>Honest Accounting: Unverified Software Capabilities</span>
                </div>
                <span className="badge muted" style={{ fontSize: 11 }}>
                  Boundary Discipline
                </span>
              </div>
              <p style={{ fontSize: 12, color: "var(--lavender-muted)", margin: "0 0 10px" }}>
                VibeCI distinguishes between what actually passed and what remains unverified. The following components exist in the repository but were not exercised by local checks:
              </p>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 10 }}>
                {report.unverified_capabilities.map((u, i) => (
                  <div
                    key={i}
                    style={{
                      padding: "10px 14px",
                      borderRadius: 6,
                      background: "rgba(0, 0, 0, 0.3)",
                      border: "1px solid rgba(255, 255, 255, 0.05)",
                    }}
                  >
                    <strong style={{ fontSize: 12, color: "var(--cream-soft)", display: "block" }}>{u.name}</strong>
                    <div style={{ fontSize: 11, color: "var(--lavender-muted)", marginTop: 2 }}>{u.reason}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* AI Coding Agent Rules Console */}
          <div
            style={{
              padding: "16px 20px",
              borderRadius: 8,
              background: "rgba(22, 16, 36, 0.7)",
              border: "1px solid rgba(255, 255, 255, 0.08)",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              flexWrap: "wrap",
              gap: 12,
            }}
          >
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, fontWeight: 700, color: "#fff" }}>
                <Bot size={16} color="var(--signal-lime)" />
                <span>AI Coding Agent Verification Rules</span>
              </div>
              <div style={{ fontSize: 12, color: "var(--lavender-muted)", marginTop: 2 }}>
                Configure Cursor, Claude Code, Copilot, or Antigravity to run VibeCI verification automatically after edits.
              </div>
              {rules && (
                <div style={{ display: "flex", gap: 6, marginTop: 6, flexWrap: "wrap" }}>
                  {Object.entries(rules).map(([agentName, ruleInfo]) => (
                    <span
                      key={agentName}
                      style={{
                        fontSize: 10,
                        padding: "1px 6px",
                        borderRadius: 3,
                        background: ruleInfo.configured ? "rgba(183, 243, 107, 0.15)" : "rgba(255, 255, 255, 0.05)",
                        color: ruleInfo.configured ? "var(--signal-lime)" : "var(--lavender-muted)",
                      }}
                    >
                      {agentName}: {ruleInfo.configured ? "Active" : "Not Set"}
                    </span>
                  ))}
                </div>
              )}
              {ruleMessage && (
                <div style={{ fontSize: 11, color: "var(--signal-lime)", marginTop: 4 }}>
                  {ruleMessage}
                </div>
              )}
            </div>

            <button
              onClick={() => void handleInstallRules()}
              className="button button-ghost"
              style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12 }}
            >
              <FileCheck2 size={14} />
              Install / Sync Rules
            </button>
          </div>
        </div>
      ) : (
        <div style={{ padding: "30px 20px", textAlign: "center", background: "rgba(22, 16, 36, 0.4)", borderRadius: 8, border: "1px dashed rgba(255,255,255,0.1)" }}>
          <ShieldCheck size={32} color="var(--lavender-muted)" style={{ margin: "0 auto 10px" }} />
          <h3 style={{ fontSize: 15, color: "#fff", margin: "0 0 6px" }}>No VibeCI Run Registered For This Project</h3>
          <p style={{ fontSize: 12, color: "var(--lavender-muted)", margin: "0 0 14px" }}>
            Click <strong>Run Preflight</strong> for a sub-second static health and credential scan, or <strong>Full Verify</strong> for complete multi-layer verification.
          </p>
          <button
            onClick={() => void handlePreflight()}
            disabled={loading || !selectedProjectId}
            className="button button-lime"
            style={{ fontSize: 13, padding: "7px 18px" }}
          >
            Run Preflight Audit
          </button>
        </div>
      )}
    </div>
  );
}
