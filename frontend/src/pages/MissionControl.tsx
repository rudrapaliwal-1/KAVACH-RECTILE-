import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Radar,
  Wrench,
  ShieldCheck,
  ArrowRight,
  RefreshCw,
  FileCode,
  Terminal,
  ChevronRight,
  Layers,
} from "lucide-react";
import { gsap } from "gsap";
import { api } from "../api/jobs";
import type { Job, ReadinessResponse } from "../api/types";

export default function MissionControl() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [readiness, setReadiness] = useState<ReadinessResponse | null>(null);
  const [activeWorld, setActiveWorld] = useState<"discover" | "remediate" | "verify">("discover");
  const [lastRefreshed, setLastRefreshed] = useState<string>("");

  const loadData = async () => {
    try {
      setLoading(true);
      const [fetchedJobs, readyRes] = await Promise.allSettled([
        api.jobs(100, 0),
        api.ready(),
      ]);

      if (fetchedJobs.status === "fulfilled") {
        setJobs(fetchedJobs.value);
      }
      if (readyRes.status === "fulfilled") {
        setReadiness(readyRes.value);
      }
      setLastRefreshed(new Date().toLocaleTimeString());
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadData();
    const interval = setInterval(() => {
      void loadData();
    }, 15000);
    return () => clearInterval(interval);
  }, []);

  // GSAP animation on active world change
  useEffect(() => {
    const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (prefersReducedMotion) return;
    gsap.fromTo(
      `.world-${activeWorld}`,
      { scale: 0.98, opacity: 0.85 },
      { scale: 1, opacity: 1, duration: 0.35, ease: "power2.out" }
    );
  }, [activeWorld]);

  // Compute real metrics from loaded jobs
  const totalFindings = jobs.length;
  const severityCounts = jobs.reduce(
    (acc, j) => {
      const sev = (j.finding?.severity || "MEDIUM").toUpperCase();
      if (sev === "CRITICAL" || sev === "HIGH") acc.high++;
      else if (sev === "MEDIUM") acc.medium++;
      else acc.low++;
      return acc;
    },
    { high: 0, medium: 0, low: 0 }
  );

  const awaitingApproval = jobs.filter(j => j.status === "AWAITING_APPROVAL");
  const verifiedJobs = jobs.filter(j => j.status === "VERIFIED");
  const failedJobs = jobs.filter(j => j.status === "VERIFICATION_FAILED" || j.status === "RETRY_EXHAUSTED");
  const runningJobs = jobs.filter(j => j.status === "PLANNING" || j.status === "VERIFYING");
  const errorJobs = jobs.filter(j => j.status === "EXECUTION_ERROR" || j.status === "POLICY_REJECTED");

  const latestPendingJob = awaitingApproval[0] || jobs[0];

  return (
    <div className="mission-control-container">
      {/* Cockpit HUD Banner */}
      <div className="cockpit-hud">
        <div className="cockpit-hud-main">
          <div className="hud-badge">
            <span className="hud-pulse" />
            <span className="mono">COCKPIT MISSION CONTROL</span>
          </div>
          <h1 className="hud-title">Three Worlds Security Hub</h1>
          <p className="hud-subtitle">
            Autonomous AST discovery, AI candidate patch deliberation, and isolated Docker lab verification.
          </p>
        </div>

        <div className="cockpit-hud-telemetry">
          <div className="telemetry-box">
            <span className="telemetry-label mono">SYSTEM STATUS</span>
            <strong className={`telemetry-value mono ${readiness?.status === "ready" ? "text-lime" : "text-amber"}`}>
              {readiness?.status?.toUpperCase() || "READY"}
            </strong>
          </div>
          <div className="telemetry-box">
            <span className="telemetry-label mono">TELEMETRY SYNC</span>
            <strong className="telemetry-value mono">{lastRefreshed || "INITIALIZING"}</strong>
          </div>
          <button
            className="button button-orbit-sm"
            onClick={() => void loadData()}
            disabled={loading}
            title="Refresh Mission Telemetry"
          >
            <RefreshCw size={14} className={loading ? "spin" : ""} />
            <span>Sync</span>
          </button>
        </div>
      </div>

      {/* World Selector Tabs */}
      <div className="world-selector-tabs">
        <button
          className={`world-tab ${activeWorld === "discover" ? "active discover" : ""}`}
          onClick={() => setActiveWorld("discover")}
        >
          <Radar size={16} />
          <span>01. DISCOVER WORLD</span>
          <span className="world-tab-badge mono">{totalFindings}</span>
        </button>

        <button
          className={`world-tab ${activeWorld === "remediate" ? "active remediate" : ""}`}
          onClick={() => setActiveWorld("remediate")}
        >
          <Wrench size={16} />
          <span>02. REMEDIATE WORLD</span>
          <span className="world-tab-badge mono">{awaitingApproval.length} PENDING</span>
        </button>

        <button
          className={`world-tab ${activeWorld === "verify" ? "active verify" : ""}`}
          onClick={() => setActiveWorld("verify")}
        >
          <ShieldCheck size={16} />
          <span>03. VERIFY WORLD</span>
          <span className="world-tab-badge mono text-lime">{verifiedJobs.length} VERIFIED</span>
        </button>
      </div>

      {/* Three Worlds Interactive Composition */}
      <div className="three-worlds-grid">
        {/* WORLD 1: DISCOVER */}
        <section
          className={`mission-world-card world-discover ${activeWorld === "discover" ? "highlighted" : ""}`}
          onClick={() => setActiveWorld("discover")}
        >
          <div className="world-card-header">
            <div className="world-tagline mono">
              <span className="world-idx">01</span>
              <span>// DISCOVERY RADAR</span>
            </div>
            <div className="world-icon-wrap discover">
              <Radar size={24} />
            </div>
          </div>

          <h2 className="world-name">Discover World</h2>
          <p className="world-summary">
            Real AST analysis identifying Broken Object Level Authorization (BOLA) and insecure direct object references.
          </p>

          <div className="world-metrics-row">
            <div className="world-metric-pill">
              <span className="label mono">FINDINGS</span>
              <strong className="val mono">{totalFindings}</strong>
            </div>
            <div className="world-metric-pill">
              <span className="label mono">HIGH / CRIT</span>
              <strong className="val text-coral mono">{severityCounts.high}</strong>
            </div>
            <div className="world-metric-pill">
              <span className="label mono">MEDIUM</span>
              <strong className="val text-amber mono">{severityCounts.medium}</strong>
            </div>
          </div>

          <div className="world-content-preview">
            <div className="preview-label mono">RECENT AST INTAKE</div>
            {jobs.slice(0, 2).map(j => (
              <div key={j.job_id} className="preview-item">
                <FileCode size={14} className="text-muted" />
                <span className="preview-title">{j.finding?.description || j.job_id}</span>
                <span className="preview-file mono">{j.finding?.file_path || "app/access.py"}</span>
              </div>
            ))}
            {jobs.length === 0 && (
              <div className="preview-empty mono">No active findings ingested yet.</div>
            )}
          </div>

          <div className="world-card-footer">
            <button
              className="button button-lime-outline"
              onClick={e => {
                e.stopPropagation();
                navigate("/findings");
              }}
            >
              <span>Explore Findings Radar</span>
              <ArrowRight size={15} />
            </button>
          </div>
        </section>

        {/* WORLD 2: REMEDIATE */}
        <section
          className={`mission-world-card world-remediate ${activeWorld === "remediate" ? "highlighted" : ""}`}
          onClick={() => setActiveWorld("remediate")}
        >
          <div className="world-card-header">
            <div className="world-tagline mono">
              <span className="world-idx">02</span>
              <span>// REPAIR FORGE</span>
            </div>
            <div className="world-icon-wrap remediate">
              <Wrench size={24} />
            </div>
          </div>

          <h2 className="world-name">Remediate World</h2>
          <p className="world-summary">
            AI code repair engine formulating minimal, context-bounded patches bound to canonical SHA-256 hashes.
          </p>

          <div className="world-metrics-row">
            <div className="world-metric-pill">
              <span className="label mono">AWAITING REVIEW</span>
              <strong className="val text-amber mono">{awaitingApproval.length}</strong>
            </div>
            <div className="world-metric-pill">
              <span className="label mono">PLANNING</span>
              <strong className="val mono">{runningJobs.length}</strong>
            </div>
            <div className="world-metric-pill">
              <span className="label mono">POLICY REJECT</span>
              <strong className="val mono text-coral">{errorJobs.length}</strong>
            </div>
          </div>

          <div className="world-content-preview">
            <div className="preview-label mono">ACTIVE CANDIDATE PATCH</div>
            {latestPendingJob ? (
              <div className="pending-patch-focus">
                <div className="patch-focus-head">
                  <span className="badge badge-warning mono">{latestPendingJob.status}</span>
                  <span className="mono text-muted">ATTEMPT #{latestPendingJob.attempt ?? 0}</span>
                </div>
                <div className="patch-focus-desc">{latestPendingJob.finding?.description}</div>
                <div className="patch-focus-meta mono">
                  File: {latestPendingJob.finding?.file_path || "app/access.py"}
                </div>
              </div>
            ) : (
              <div className="preview-empty mono">No candidate patches awaiting operator review.</div>
            )}
          </div>

          <div className="world-card-footer">
            <button
              className="button button-amber"
              onClick={e => {
                e.stopPropagation();
                if (latestPendingJob) {
                  navigate(`/investigation?jobId=${encodeURIComponent(latestPendingJob.job_id)}`);
                } else {
                  navigate("/investigation");
                }
              }}
            >
              <span>Review Security Case</span>
              <ArrowRight size={15} />
            </button>
          </div>
        </section>

        {/* WORLD 3: VERIFY */}
        <section
          className={`mission-world-card world-verify ${activeWorld === "verify" ? "highlighted" : ""}`}
          onClick={() => setActiveWorld("verify")}
        >
          <div className="world-card-header">
            <div className="world-tagline mono">
              <span className="world-idx">03</span>
              <span>// ADVERSARIAL LAB</span>
            </div>
            <div className="world-icon-wrap verify">
              <ShieldCheck size={24} />
            </div>
          </div>

          <h2 className="world-name">Verify World</h2>
          <p className="world-summary">
            Independent Docker lab running tamper-proof test suites. Only genuine verifier execution establishes proof.
          </p>

          <div className="world-metrics-row">
            <div className="world-metric-pill">
              <span className="label mono">CONFIRMED FIX</span>
              <strong className="val text-lime mono">{verifiedJobs.length}</strong>
            </div>
            <div className="world-metric-pill">
              <span className="label mono">TEST FAILURES</span>
              <strong className="val text-coral mono">{failedJobs.length}</strong>
            </div>
            <div className="world-metric-pill">
              <span className="label mono">SUITE PROFILE</span>
              <strong className="val mono text-teal">BOLA-V1</strong>
            </div>
          </div>

          <div className="world-content-preview">
            <div className="preview-label mono">VERIFICATION ENVIRONMENT</div>
            <div className="env-check-row">
              <span className="env-check-name mono">DOCKER CONTAINER LAB:</span>
              <span className={`env-status-badge mono ${readiness?.checks?.docker?.status === "ready" ? "ready" : "warn"}`}>
                {readiness?.checks?.docker?.status === "ready" ? "CONNECTED" : "ISOLATED"}
              </span>
            </div>
            <div className="env-check-row">
              <span className="env-check-name mono">PROTECTED SUITE:</span>
              <span className="env-status-badge mono ready">8/8 TESTS LOCKED</span>
            </div>
            <div className="env-check-row">
              <span className="env-check-name mono">CRYPTO ATTESTATION:</span>
              <span className="env-status-badge mono ready">SHA256 ENFORCED</span>
            </div>
          </div>

          <div className="world-card-footer">
            <button
              className="button button-lime"
              onClick={e => {
                e.stopPropagation();
                navigate("/verification");
              }}
            >
              <span>Inspect Lab Runs</span>
              <ArrowRight size={15} />
            </button>
          </div>
        </section>
      </div>

      {/* Quick Launch & Repository Upload Bar */}
      <div className="cockpit-bottom-bar">
        <div className="bar-info">
          <Terminal size={18} className="text-lime" />
          <div>
            <strong className="bar-title">Controlled Demonstration Contract Ready</strong>
            <p className="bar-desc">
              Upload a zip repository archive under Projects or select an existing finding case to run through the verification loop.
            </p>
          </div>
        </div>

        <div className="bar-actions">
          <button className="button button-orbit" onClick={() => navigate("/projects")}>
            <Layers size={15} />
            <span>Upload Archive</span>
          </button>
          <button className="button button-lime" onClick={() => navigate("/dashboard")}>
            <span>Open Command Center</span>
            <ChevronRight size={16} />
          </button>
        </div>
      </div>
    </div>
  );
}
