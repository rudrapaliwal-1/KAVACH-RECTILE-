import { useEffect, useState } from "react";
import {
  Activity,
  CheckCircle2,
  Clock3,
  ShieldAlert,
  ArrowUpRight,
  RefreshCw,
  Zap,
  CircleCheck,
  FileSearch,
  Server,
  Layers,
  Wrench,
  ChevronRight,
} from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "../api/jobs";
import { request } from "../api/client";
import { useJobs } from "../hooks/useJobs";
import StatCard from "../components/StatCard";
import FindingsTable from "../components/FindingsTable";
import StatusBadge from "../components/StatusBadge";
import type { ReadinessResponse } from "../api/types";

export default function Dashboard() {
  const { jobs, loading, error, refresh } = useJobs();
  const [projects, setProjects] = useState<{ id: string; name?: string }[]>([]);
  const [scans, setScans] = useState<
    { id: string; status: string; project_name: string; finding_count: number; created_at: string }[]
  >([]);
  const [patches, setPatches] = useState<
    {
      id: string;
      approval_status: string;
      verification_status: string;
      project_name: string;
      category: string;
      created_at: string;
    }[]
  >([]);
  const [scanFindings, setScanFindings] = useState<{ id: string }[]>([]);
  const [dataError, setDataError] = useState("");
  const [summaryLoading, setSummaryLoading] = useState(true);
  const [readiness, setReadiness] = useState<ReadinessResponse | null>(null);
  const [health, setHealth] = useState<"checking" | "online" | "offline">("checking");

  async function refreshSummary() {
    setSummaryLoading(true);
    try {
      const [p, s, f, patchRows, readyRes] = await Promise.allSettled([
        request<{ id: string }[]>("/api/projects"),
        request<typeof scans>("/api/scans"),
        request<{ id: string }[]>("/api/scan-findings"),
        request<typeof patches>("/api/scan-patches"),
        api.ready(),
      ]);

      if (p.status === "fulfilled") setProjects(p.value);
      if (s.status === "fulfilled") setScans(s.value);
      if (f.status === "fulfilled") setScanFindings(f.value);
      if (patchRows.status === "fulfilled") setPatches(patchRows.value);
      if (readyRes.status === "fulfilled") setReadiness(readyRes.value);
      setDataError("");
    } catch (e) {
      setDataError(e instanceof Error ? e.message : "Could not load scan summary");
    } finally {
      setSummaryLoading(false);
    }
  }

  useEffect(() => {
    let active = true;
    setSummaryLoading(true);

    Promise.allSettled([
      request<{ id: string }[]>("/api/projects"),
      request<typeof scans>("/api/scans"),
      request<{ id: string }[]>("/api/scan-findings"),
      request<typeof patches>("/api/scan-patches"),
      api.ready(),
    ]).then(([p, s, f, patchRows, readyRes]) => {
      if (!active) return;
      if (p.status === "fulfilled") setProjects(p.value);
      if (s.status === "fulfilled") setScans(s.value);
      if (f.status === "fulfilled") setScanFindings(f.value);
      if (patchRows.status === "fulfilled") setPatches(patchRows.value);
      if (readyRes.status === "fulfilled") setReadiness(readyRes.value);
      setDataError("");
      setSummaryLoading(false);
    });

    api.health()
      .then(() => {
        if (active) setHealth("online");
      })
      .catch(() => {
        if (active) setHealth("offline");
      });

    return () => {
      active = false;
    };
  }, []);

  const awaiting =
    jobs.filter(j => j.status === "AWAITING_APPROVAL").length +
    patches.filter(p => p.approval_status === "PENDING").length;
  const verified = jobs.filter(j => j.status === "VERIFIED").length;
  const failed = jobs.filter(j =>
    ["VERIFICATION_FAILED", "POLICY_REJECTED", "EXECUTION_ERROR", "RETRY_EXHAUSTED"].includes(
      String(j.status)
    )
  ).length;
  const total = jobs.length;

  const distribution = [
    "AWAITING_APPROVAL",
    "VERIFYING",
    "VERIFIED",
    "VERIFICATION_FAILED",
    "POLICY_REJECTED",
    "EXECUTION_ERROR",
  ].map(status => ({
    status,
    count: jobs.filter(j => j.status === status).length,
  }));

  return (
    <div className="page">
      <div className="page-heading">
        <div>
          <div className="hero-eyebrow">
            <span className="eyebrow-accent mono">COMMAND CENTER</span>
            <span className="eyebrow-line" />
            <span className="mono text-muted">EDITORIAL SECURITY OPERATIONS</span>
          </div>
          <h1>Security Command Center</h1>
          <p>
            Track autonomous remediation pipelines, candidate patch hashes, operator approvals,
            and adversarial Docker verification outcomes.
          </p>
        </div>

        <div className="header-action-group" style={{ display: "flex", gap: "12px", alignItems: "center" }}>
          <button
            className="button button-orbit"
            onClick={() => {
              void refresh();
              void refreshSummary();
            }}
            disabled={loading}
          >
            <RefreshCw size={15} className={loading ? "spin" : ""} />
            <span>Sync Live Telemetry</span>
          </button>
          <Link className="button button-lime" to="/projects">
            <span>Upload Repository</span>
            <ChevronRight size={15} />
          </Link>
        </div>
      </div>

      {/* Connection & Readiness Strip */}
      <div className="cockpit-bottom-bar" style={{ marginBottom: "26px", padding: "14px 22px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "16px", flexWrap: "wrap", fontSize: "11px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <span className={`pulse-dot ${health === "offline" ? "offline" : ""}`} />
            <span className="mono">
              API SERVER: <strong>{health === "checking" ? "CHECKING…" : health === "online" ? "ONLINE" : "UNAVAILABLE"}</strong>
            </span>
          </div>

          <span className="telemetry-divider">/</span>

          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <Server size={13} className="text-lime" />
            <span className="mono">
              READINESS:{" "}
              <strong className={readiness?.status === "ready" ? "text-lime" : "text-amber"}>
                {readiness?.status?.toUpperCase() || "PROBING"}
              </strong>
            </span>
          </div>

          <span className="telemetry-divider">/</span>

          <span className="mono text-muted">DATA: AUTHENTICATED SQLITE AUDIT DATABASE</span>

          {(error || dataError) && (
            <span className="connection-error mono text-coral" style={{ marginLeft: "auto" }}>
              {error || dataError}
            </span>
          )}
        </div>

        <Link to="/settings" className="button button-ghost-sm mono" style={{ flexShrink: 0 }}>
          Diagnostics Grid ↗
        </Link>
      </div>

      {/* High-Density Stats Grid */}
      <div className="stats-grid">
        <StatCard
          label="Target Projects"
          value={summaryLoading ? "—" : projects.length}
          detail="Active repository stores"
          icon={Layers}
        />
        <StatCard
          label="Scan Findings"
          value={summaryLoading ? "—" : scanFindings.length}
          detail="Static code defect matches"
          icon={ShieldAlert}
          tone="amber"
        />
        <StatCard
          label="Remediation Jobs"
          value={loading ? "—" : total}
          detail="Autonomous workflow cases"
          icon={FileSearch}
        />
        <StatCard
          label="Awaiting Approval"
          value={loading || summaryLoading ? "—" : awaiting}
          detail="Explicit human sign-off needed"
          icon={Clock3}
          tone="amber"
        />
        <StatCard
          label="AI Patch Drafts"
          value={summaryLoading ? "—" : patches.length}
          detail="Qwen candidate revisions"
          icon={Wrench}
        />
        <StatCard
          label="Confirmed Verified"
          value={loading ? "—" : verified}
          detail="Passed all 8 protected tests"
          icon={CheckCircle2}
          tone="lime"
        />
        <StatCard
          label="Adversarial Failures"
          value={loading ? "—" : failed}
          detail="Rejected or test failed"
          icon={ShieldAlert}
          tone="coral"
        />
        <StatCard
          label="Lab Attestation"
          value="SHA-256"
          detail="Cryptographic hash binding"
          icon={CircleCheck}
          tone="teal"
        />
      </div>

      {/* Main Operational Split Grid */}
      <div className="dashboard-grid">
        {/* Remediation Queue Table */}
        <section className="panel recent-panel">
          <div className="panel-heading">
            <div>
              <div className="workspace-label mono">REMEDIATION QUEUE</div>
              <h2>Active Security Cases</h2>
            </div>
            <Link to="/findings" className="text-link mono">
              All Cases <ArrowUpRight size={14} />
            </Link>
          </div>

          {loading ? (
            <div className="loading-state">
              <RefreshCw size={17} className="spin" /> Loading security cases from backend API…
            </div>
          ) : (
            <FindingsTable jobs={jobs.slice(0, 7)} />
          )}
        </section>

        {/* Workflow State Distribution */}
        <section className="panel distribution-panel">
          <div className="panel-heading">
            <div>
              <div className="workspace-label mono">TELEMETRY</div>
              <h2>Lifecycle Distribution</h2>
            </div>
            <Activity size={18} className="text-lime" />
          </div>

          {!loading && !jobs.length ? (
            <div className="empty-state">
              Workflow metrics appear when jobs are available from the API.
            </div>
          ) : (
            <div className="distribution-list">
              {distribution.map(d => (
                <div className="distribution-item" key={d.status}>
                  <div className="distribution-label">
                    <StatusBadge status={d.status} />
                    <strong className="mono">{d.count}</strong>
                  </div>
                  <div className="meter">
                    <span
                      style={{
                        width: `${total ? (d.count / total) * 100 : 0}%`,
                        background:
                          d.status === "VERIFIED"
                            ? "var(--signal-lime)"
                            : d.status === "AWAITING_APPROVAL"
                            ? "var(--accent-amber)"
                            : d.status.includes("FAIL") || d.status.includes("REJECT")
                            ? "var(--threat-coral)"
                            : "var(--orbit-violet)",
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          )}

          <div className="scope-note">
            <Zap size={15} />
            <span>
              Verification outcomes are established exclusively by the independent verifier running
              in isolated containers.
            </span>
          </div>
        </section>
      </div>

      {/* Editorial Process Lifecycle Banner */}
      <section className="workflow-strip" style={{ marginTop: "28px" }}>
        <div>
          <span className="workflow-step mono">01</span>
          <div>
            <strong>Intake & AST Scan</strong>
            <small>Finding & root cause extraction</small>
          </div>
        </div>
        <span className="workflow-arrow text-lime">→</span>
        <div>
          <span className="workflow-step mono">02</span>
          <div>
            <strong>AI Patch Generation</strong>
            <small>Canonical SHA-256 hash calculation</small>
          </div>
        </div>
        <span className="workflow-arrow text-lime">→</span>
        <div>
          <span className="workflow-step mono">03</span>
          <div>
            <strong>Explicit Human Approval</strong>
            <small>Strict hash & identity binding</small>
          </div>
        </div>
        <span className="workflow-arrow text-lime">→</span>
        <div>
          <span className="workflow-step verified mono">04</span>
          <div>
            <strong>Adversarial Verification</strong>
            <small>Protected test suite in Docker lab</small>
          </div>
        </div>
      </section>
    </div>
  );
}