import { useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import {
  ArrowLeft, RefreshCw, BrainCircuit, FileCode2, History, ShieldCheck,
  Download, FileJson, AlertTriangle, CheckCircle2, Code, Layers, Check, Copy, CheckCheck
} from "lucide-react";
import { useJobDetails } from "../hooks/useJobDetails";
import StatusBadge from "../components/StatusBadge";
import PatchDiffViewer from "../components/PatchDiffViewer";
import ApprovalPanel from "../components/ApprovalPanel";
import ActivityTimeline from "../components/ActivityTimeline";
import VerificationPanel from "../components/VerificationPanel";
import { api } from "../api/jobs";

export default function Investigation() {
  const { jobId: routeJobId } = useParams();
  const [searchParams] = useSearchParams();
  const jobId = routeJobId || searchParams.get("jobId") || "";
  const { job, patch, events, evidence, source, loading, error, refresh } = useJobDetails(jobId);
  const [verifyBusy, setVerifyBusy] = useState(false);
  const [verifyError, setVerifyError] = useState("");
  const [activeCodeTab, setActiveCodeTab] = useState<"diff" | "source">("diff");
  const [copiedHash, setCopiedHash] = useState(false);

  const canVerify = Boolean(
    job?.status === "VERIFYING" &&
    patch?.patch_hash &&
    !job.verification_running &&
    (!job.verification || job.verification.patch_hash !== patch.patch_hash)
  );

  async function verify() {
    if (!jobId || verifyBusy || !canVerify) return;
    setVerifyBusy(true);
    setVerifyError("");
    try {
      await api.verify(jobId);
      await refresh();
    } catch (e) {
      setVerifyError(e instanceof Error ? e.message : "Verification request failed.");
    } finally {
      setVerifyBusy(false);
    }
  }

  function downloadEvidence() {
    if (!evidence || !jobId) return;
    const blob = new Blob([JSON.stringify(evidence, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `kavach-x-evidence-${jobId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function copyHash(hash: string) {
    navigator.clipboard.writeText(hash).then(() => {
      setCopiedHash(true);
      setTimeout(() => setCopiedHash(false), 2000);
    });
  }

  if (!jobId) {
    return (
      <div className="page">
        <div className="error-state">
          <h2>Select a job to investigate</h2>
          <p>Open a job from Findings or the dashboard.</p>
          <Link to="/findings" className="button button-primary">Browse findings</Link>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="page">
        <div className="loading-state">
          <RefreshCw size={18} className="spin" /> Loading unified security case from API…
        </div>
      </div>
    );
  }

  if (error || !job) {
    return (
      <div className="page">
        <div className="error-state">
          <h2>Unable to load investigation</h2>
          <p>{error || "The backend returned no job."}</p>
          <p>Check the job ID and API connectivity.</p>
          <button className="button button-secondary" onClick={() => void refresh()}>Retry</button>
          <Link to="/findings" className="text-link">Back to findings</Link>
        </div>
      </div>
    );
  }

  const finding = job.finding;
  const runs = evidence?.verification_runs || [];
  const revisions = evidence?.patch_attempts || (patch ? [patch] : []);
  const approvals = evidence?.approvals || [];
  const currentApproval = approvals.filter(a => a.attempt === (patch?.attempt ?? job.attempt)).at(-1);

  return (
    <div className="page">
      {/* Top Navigation & Actions */}
      <div className="page-heading">
        <div>
          <Link to="/findings" className="back-link"><ArrowLeft size={14} /> Findings</Link>
          <div className="eyebrow">UNIFIED SECURITY CASE / {job.job_id}</div>
          <h1>{finding?.id || job.finding_id || job.job_id}</h1>
          <p>{finding?.description || job.summary || "AI-assisted security remediation case managed by KAVACH-X."}</p>
        </div>
        <div className="heading-actions">
          <StatusBadge status={job.status} />
          <button className="button button-secondary" onClick={() => void refresh()} title="Refresh case details">
            <RefreshCw size={14} /> Refresh
          </button>
          {evidence && (
            <button className="button button-secondary" onClick={downloadEvidence} title="Export persisted audit evidence as JSON">
              <Download size={14} /> Download Evidence JSON
            </button>
          )}
        </div>
      </div>

      {/* State-specific Banners */}
      {job.status === "EXECUTION_ERROR" && (
        <div className="error-banner" role="alert">
          <AlertTriangle size={16} />
          <div>
            <strong>Backend Execution Error</strong>
            <p style={{ margin: "2px 0 0" }}>
              The verifier or model provider encountered an execution error. Check Settings for readiness diagnostics (Docker daemon, verifier image, Ollama service).
            </p>
          </div>
        </div>
      )}

      {job.status === "POLICY_REJECTED" && (
        <div className="error-banner" role="alert">
          <AlertTriangle size={16} />
          <div>
            <strong>Proposal Policy Rejected</strong>
            <p style={{ margin: "2px 0 0" }}>
              The proposed patch violated deterministic backend security policy:
              {patch?.policy_details?.reasons?.map((r, i) => <span key={i} style={{ display: "block", marginTop: 2 }}>• {r}</span>)}
            </p>
          </div>
        </div>
      )}

      {job.status === "VERIFICATION_FAILED" && (
        <div className="notice" style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.25)" }}>
          <AlertTriangle size={16} className="text-red" />
          <div>
            <strong>Verification Failed on Attempt {job.attempt}</strong>
            <p style={{ margin: "2px 0 0" }}>
              Protected regression tests failed in the isolated environment. Sanitized failure feedback has been supplied to Agent B for reflection.
            </p>
          </div>
        </div>
      )}

      {job.status === "RETRY_EXHAUSTED" && (
        <div className="error-banner" role="alert">
          <AlertTriangle size={16} />
          <div>
            <strong>Retry Exhausted</strong>
            <p style={{ margin: "2px 0 0" }}>
              Maximum revision attempts reached without passing all required tests. Human operator review is recommended.
            </p>
          </div>
        </div>
      )}

      {job.status === "VERIFIED" && (
        <div className="notice" style={{ background: "rgba(34,197,94,0.12)", border: "1px solid rgba(34,197,94,0.3)" }}>
          <CheckCircle2 size={16} style={{ color: "#4ade80" }} />
          <div>
            <strong style={{ color: "#4ade80" }}>Cryptographically Verified Remediated State</strong>
            <p style={{ margin: "2px 0 0" }}>
              The approved patch passed all protected tests in the independent Docker verification laboratory. Cryptographic attestation digest matches persisted evidence.
            </p>
          </div>
        </div>
      )}

      {/* Case Overview Metrics */}
      <div className="investigation-summary">
        <div>
          <span>Vulnerability</span>
          <strong>{finding?.type?.replaceAll("_", " ") || "Not provided"}</strong>
        </div>
        <div>
          <span>Severity</span>
          <strong className={`severity ${String(finding?.severity || "").toLowerCase()}`}>
            {finding?.severity || "—"}
          </strong>
        </div>
        <div>
          <span>Affected File</span>
          <strong><FileCode2 size={14} />{finding?.file_path || "—"}</strong>
        </div>
        <div>
          <span>Attempt</span>
          <strong>Attempt {patch?.attempt ?? job.attempt ?? 0}</strong>
        </div>
        <div>
          <span>Target App</span>
          <code>{String(job.target_app_id || evidence?.target_app_id || "bola-demo-v1")}</code>
        </div>
        <div>
          <span>Source Revision</span>
          <code style={{ fontSize: "0.75rem" }}>
            {evidence?.target_binding?.source_revision ? evidence.target_binding.source_revision.slice(0, 16) + "…" : "Authorized"}
          </code>
        </div>
      </div>

      {/* Main Investigation Grid */}
      <div className="investigation-grid">
        <div className="investigation-main">
          {/* Code Inspection Section: Unified Diff & Source Code */}
          <section className="panel">
            <div className="panel-heading" style={{ flexWrap: "wrap", gap: 10 }}>
              <div>
                <div className="eyebrow">CODE INSPECTION</div>
                <h2><FileCode2 size={18} /> Proposed remediation & source context</h2>
              </div>
              <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                <button
                  type="button"
                  className={`button ${activeCodeTab === "diff" ? "button-primary" : "button-secondary"}`}
                  onClick={() => setActiveCodeTab("diff")}
                  style={{ fontSize: "0.8rem", padding: "4px 10px" }}
                >
                  <Layers size={13} /> Proposed Unified Diff
                </button>
                <button
                  type="button"
                  className={`button ${activeCodeTab === "source" ? "button-primary" : "button-secondary"}`}
                  onClick={() => setActiveCodeTab("source")}
                  style={{ fontSize: "0.8rem", padding: "4px 10px" }}
                >
                  <Code size={13} /> Original Source Code
                </button>
                <span className="version-pill">Attempt {patch?.attempt ?? job.attempt ?? 0}</span>
              </div>
            </div>

            {activeCodeTab === "diff" ? (
              <>
                <PatchDiffViewer patch={patch} />
                <div className="patch-explanation">
                  <BrainCircuit size={17} />
                  <div>
                    <strong>AI Remediation Rationale</strong>
                    <p>{patch?.explanation || "No patch explanation was included in the backend proposal."}</p>
                  </div>
                </div>
              </>
            ) : (
              <div className="source-viewer" style={{ padding: "12px 16px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8, fontSize: "0.85rem" }}>
                  <span><FileCode2 size={14} style={{ display: "inline", verticalAlign: "middle" }} /> <strong>{source?.file_path || finding?.file_path || "app/access.py"}</strong></span>
                  <span style={{ color: "var(--text-muted, #889)" }}>Authorized bounded context</span>
                </div>
                {source?.content ? (
                  <pre
                    className="diff-code"
                    style={{ maxHeight: 420, overflow: "auto", background: "rgba(0,0,0,0.3)", padding: 12, borderRadius: 6 }}
                  >
                    {source.content.split("\n").map((line, idx) => (
                      <div key={idx} className="diff-line context">
                        <span className="line-number">{idx + 1}</span>
                        <span className="line-content">{line || " "}</span>
                      </div>
                    ))}
                  </pre>
                ) : (
                  <div className="empty-state">Source file context not available or outside authorized target boundary.</div>
                )}
              </div>
            )}

            {/* Canonical Hash & Integrity */}
            {patch?.patch_hash && (
              <div
                style={{
                  margin: "12px 16px 16px",
                  padding: "10px 14px",
                  background: "rgba(0,0,0,0.25)",
                  borderRadius: 6,
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  flexWrap: "wrap",
                  gap: 8,
                }}
              >
                <div>
                  <span style={{ fontSize: "0.75rem", color: "var(--text-muted, #889)", display: "block" }}>
                    CANONICAL PATCH HASH (SHA-256)
                  </span>
                  <code style={{ fontSize: "0.82rem", wordBreak: "break-all" }}>{patch.patch_hash}</code>
                </div>
                <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  <span
                    style={{
                      fontSize: "0.72rem",
                      padding: "2px 8px",
                      borderRadius: 4,
                      fontWeight: 600,
                      background: "rgba(34,197,94,0.15)",
                      color: "#4ade80",
                    }}
                  >
                    INTEGRITY VALID
                  </span>
                  <button
                    type="button"
                    className="icon-button"
                    onClick={() => copyHash(patch.patch_hash)}
                    title="Copy hash"
                    style={{ padding: "4px 8px", fontSize: "0.75rem" }}
                  >
                    {copiedHash ? <CheckCheck size={13} className="text-cyan" /> : <Copy size={13} />}
                  </button>
                </div>
              </div>
            )}
          </section>

          {/* Adversarial Verification Panel */}
          <section className="panel">
            <div className="panel-heading">
              <div>
                <div className="eyebrow">ADVERSARIAL VERIFICATION</div>
                <h2><ShieldCheck size={18} /> Isolated Docker Test Evidence</h2>
              </div>
            </div>
            <p className="fine-print">
              Only the independent Docker verifier establishes verification outcomes. Untrusted patches are never executed directly on the host.
            </p>
            <VerificationPanel result={job.verification} />
            {verifyError && <div className="error-banner">{verifyError}</div>}
            <div className="verify-action">
              <button
                className="button button-primary"
                disabled={verifyBusy || !canVerify}
                onClick={() => void verify()}
              >
                {verifyBusy ? <RefreshCw size={15} className="spin" /> : <ShieldCheck size={15} />}
                {verifyBusy ? "Executing isolated tests…" : "Request verification"}
              </button>
              <span>
                {job.status === "AWAITING_APPROVAL"
                  ? "Human approval of the exact patch hash is required before verification."
                  : job.status === "VERIFYING"
                  ? "Ready for verification. Backend invokes the isolated Docker environment."
                  : "Verification status is final for this attempt."}
              </span>
            </div>
          </section>

          {/* Verification Run History */}
          {runs.length > 0 && (
            <section className="panel">
              <div className="panel-heading">
                <div>
                  <div className="eyebrow">AUDIT LEDGER</div>
                  <h2><History size={18} /> Verification Run History ({runs.length})</h2>
                </div>
              </div>
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", textAlign: "left", fontSize: "0.85rem", borderCollapse: "collapse" }}>
                  <thead>
                    <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.1)", color: "var(--text-muted, #889)" }}>
                      <th style={{ padding: "8px 12px" }}>Run ID</th>
                      <th style={{ padding: "8px 12px" }}>Status</th>
                      <th style={{ padding: "8px 12px" }}>Tests</th>
                      <th style={{ padding: "8px 12px" }}>Duration</th>
                      <th style={{ padding: "8px 12px" }}>Attestation</th>
                      <th style={{ padding: "8px 12px" }}>Patch Hash</th>
                    </tr>
                  </thead>
                  <tbody>
                    {runs.map(run => (
                      <tr key={run.id} style={{ borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                        <td style={{ padding: "8px 12px" }}><code>{run.id.slice(0, 12)}…</code></td>
                        <td style={{ padding: "8px 12px" }}><StatusBadge status={run.status} /></td>
                        <td style={{ padding: "8px 12px" }}>
                          {run.result?.tests_passed ?? 0} passed / {run.result?.tests_failed ?? 0} failed
                        </td>
                        <td style={{ padding: "8px 12px" }}>
                          {run.result?.duration_ms != null ? `${(run.result.duration_ms / 1000).toFixed(2)}s` : "—"}
                        </td>
                        <td style={{ padding: "8px 12px" }}>
                          <span style={{ color: run.attestation_integrity === "VALID" ? "#4ade80" : "#f87171" }}>
                            {run.attestation_integrity || (run.attestation ? "VALID" : "PENDING")}
                          </span>
                        </td>
                        <td style={{ padding: "8px 12px" }}>
                          <code style={{ fontSize: "0.75rem" }}>{run.patch_hash.slice(0, 16)}…</code>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {/* Revision History */}
          {revisions.length > 0 && (
            <section className="panel">
              <div className="panel-heading">
                <div>
                  <div className="eyebrow">VERSIONING</div>
                  <h2><Layers size={18} /> Revision History ({revisions.length})</h2>
                </div>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                {revisions.map((rev, index) => (
                  <div
                    key={index}
                    style={{
                      background: "rgba(0,0,0,0.2)",
                      borderRadius: 6,
                      padding: "10px 14px",
                      fontSize: "0.85rem",
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                      <strong>Attempt {rev.attempt ?? index}</strong>
                      <span style={{ fontSize: "0.75rem", color: "var(--text-muted, #889)" }}>
                        Policy: <strong style={{ color: rev.policy_status === "PASSED" ? "#4ade80" : "#f87171" }}>{rev.policy_status || "PASSED"}</strong>
                      </span>
                    </div>
                    <p style={{ margin: "2px 0 6px", color: "var(--text-secondary, #ccc)" }}>{rev.root_cause || rev.explanation || "Proposal recorded."}</p>
                    <code style={{ fontSize: "0.75rem", wordBreak: "break-all" }}>{rev.patch_hash}</code>
                  </div>
                ))}
              </div>
            </section>
          )}
        </div>

        {/* Sidebar: Approval, Root Cause & Audit Trail */}
        <div className="investigation-side">
          <ApprovalPanel
            job={job}
            patch={patch}
            approval={currentApproval}
            onUpdated={() => void refresh()}
          />

          <section className="panel">
            <div className="panel-heading">
              <div>
                <div className="eyebrow">ROOT CAUSE</div>
                <h3><BrainCircuit size={16} /> Analysis</h3>
              </div>
            </div>
            <p className="analysis-copy">{patch?.root_cause || "Root-cause analysis has not been supplied yet."}</p>
          </section>

          {/* Persisted Evidence Summary */}
          {evidence && (
            <section className="panel">
              <div className="panel-heading">
                <div>
                  <div className="eyebrow">PERSISTED EVIDENCE</div>
                  <h3><FileJson size={16} /> Attestation & Integrity</h3>
                </div>
              </div>
              <div style={{ fontSize: "0.85rem", display: "flex", flexDirection: "column", gap: 8 }}>
                <div>Conclusion: <strong style={{ color: evidence.conclusion === "VERIFIED" ? "#4ade80" : "#f59e0b" }}>{evidence.conclusion || "PENDING"}</strong></div>
                <div>Source Revision: <strong>{evidence.source_revision_current ? "MATCHES WORKSPACE" : "RECORDED"}</strong></div>
                {evidence.target_binding && (
                  <div>Profile: <code>{evidence.target_binding.verification_profile}</code></div>
                )}
                {evidence.integrity_issues && evidence.integrity_issues.length > 0 ? (
                  <div style={{ color: "#f87171" }}>
                    <strong>Integrity issues:</strong>
                    {evidence.integrity_issues.map((issue, idx) => <div key={idx}>• {issue}</div>)}
                  </div>
                ) : (
                  <div style={{ color: "#4ade80", display: "flex", alignItems: "center", gap: 4 }}>
                    <Check size={14} /> No integrity discrepancies detected
                  </div>
                )}
                <button
                  className="button button-secondary"
                  onClick={downloadEvidence}
                  style={{ marginTop: 6, width: "100%", justifyContent: "center" }}
                >
                  <Download size={14} /> Download Evidence JSON
                </button>
              </div>
            </section>
          )}

          <section className="panel">
            <div className="panel-heading">
              <div>
                <div className="eyebrow">AUDIT TRAIL</div>
                <h3><History size={16} /> Workflow Events</h3>
              </div>
            </div>
            <ActivityTimeline events={events} />
          </section>
        </div>
      </div>
    </div>
  );
}
