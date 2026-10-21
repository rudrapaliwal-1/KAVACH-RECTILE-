import { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import {
  GitCompare,
  PlusCircle,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Lock,
  Layers,
  Sparkles,
  Info,
  RefreshCw,
  FileCode,
  ExternalLink,
} from "lucide-react";
import { api } from "../api/jobs";
import type { CandidatePatch, ComparisonReport, Job, PatchIntakePayload } from "../api/types";
import StatusBadge from "../components/StatusBadge";

const PRESET_SOURCES = [
  "Claude 3.7 Sonnet",
  "Cursor / Claude-3.5",
  "GitHub Copilot",
  "DeepSeek-R1",
  "Manual Developer",
];

const SAMPLE_DIFF = `diff --git a/app/access.py b/app/access.py
--- a/app/access.py
+++ b/app/access.py
@@ -1 +1 @@
-return document
+return document if owner == user else None
`;

export default function PatchLab() {
  const location = useLocation();
  const navigate = useNavigate();
  const queryJobId = new URLSearchParams(location.search).get("jobId") || "";

  // State
  const [jobs, setJobs] = useState<Job[]>([]);
  const [selectedTargetJobId, setSelectedTargetJobId] = useState(queryJobId);
  const [candidates, setCandidates] = useState<CandidatePatch[]>([]);
  const [selectedCandidateJobIds, setSelectedCandidateJobIds] = useState<string[]>([]);
  const [comparisonReport, setComparisonReport] = useState<ComparisonReport | null>(null);

  // Intake Form State
  const [showIntakeForm, setShowIntakeForm] = useState(false);
  const [authoringSource, setAuthoringSource] = useState(PRESET_SOURCES[0]);
  const [customAuthor, setCustomAuthor] = useState("");
  const [patchText, setPatchText] = useState(SAMPLE_DIFF);
  const [rootCause, setRootCause] = useState("Missing object-level access verification on document retrieval");
  const [explanation, setExplanation] = useState("Checks whether requesting user owns the document before returning payload");
  const [intakeBusy, setIntakeBusy] = useState(false);
  const [intakeError, setIntakeError] = useState("");
  const [intakeSuccess, setIntakeSuccess] = useState("");

  // Loading States
  const [loadingList, setLoadingList] = useState(false);
  const [loadingCompare, setLoadingCompare] = useState(false);
  const [actionBusyJobId, setActionBusyJobId] = useState<string | null>(null);

  // Load existing jobs for target selection
  useEffect(() => {
    async function initJobs() {
      try {
        const list = await api.jobs(50, 0);
        setJobs(list);
        if (!selectedTargetJobId && list.length > 0) {
          setSelectedTargetJobId(list[0].job_id);
        }
      } catch {
        // ignore
      }
    }
    void initJobs();
  }, []);

  // Load candidate patches
  async function loadCandidates() {
    setLoadingList(true);
    try {
      const list = await api.listCandidates();
      setCandidates(list);
      // Auto-select first two or three if not selected
      if (selectedCandidateJobIds.length === 0 && list.length >= 2) {
        const defaultSelected = list.slice(0, 3).map(c => c.job_id);
        setSelectedCandidateJobIds(defaultSelected);
        void runComparison(defaultSelected);
      }
    } catch {
      // ignore
    } finally {
      setLoadingList(false);
    }
  }

  useEffect(() => {
    void loadCandidates();
  }, []);

  // Run Comparison
  async function runComparison(idsToCompare?: string[]) {
    const ids = idsToCompare || selectedCandidateJobIds;
    if (ids.length === 0) {
      setComparisonReport(null);
      return;
    }
    setLoadingCompare(true);
    try {
      const report = await api.compareCandidates(ids);
      setComparisonReport(report);
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingCompare(false);
    }
  }

  function toggleCandidateSelection(jid: string) {
    let next: string[];
    if (selectedCandidateJobIds.includes(jid)) {
      next = selectedCandidateJobIds.filter(id => id !== jid);
    } else {
      next = [...selectedCandidateJobIds, jid];
    }
    setSelectedCandidateJobIds(next);
    if (next.length > 0) {
      void runComparison(next);
    } else {
      setComparisonReport(null);
    }
  }

  // Handle Patch Intake
  async function handleIntakeSubmit(e: React.FormEvent) {
    e.preventDefault();
    setIntakeBusy(true);
    setIntakeError("");
    setIntakeSuccess("");

    const sourceName = customAuthor.trim() || authoringSource;
    const payload: PatchIntakePayload = {
      target_app_id: "bola-demo-v1",
      job_id: selectedTargetJobId || undefined,
      patch_text: patchText,
      authoring_source: sourceName,
      root_cause: rootCause,
      explanation: explanation,
    };

    try {
      const res = await api.intakePatch(payload);
      setIntakeSuccess(`Candidate patch registered as ${res.job_id} (${res.policy_status})`);
      setShowIntakeForm(false);
      await loadCandidates();
      // Select the new candidate automatically
      const nextSelected = Array.from(new Set([...selectedCandidateJobIds, res.job_id]));
      setSelectedCandidateJobIds(nextSelected);
      void runComparison(nextSelected);
    } catch (err: unknown) {
      setIntakeError(err instanceof Error ? err.message : "Failed to intake patch candidate");
    } finally {
      setIntakeBusy(false);
    }
  }

  // Quick Approval Handler
  async function handleApprove(jid: string, pHash: string) {
    setActionBusyJobId(jid);
    try {
      await api.approval(jid, pHash, "APPROVE");
      await loadCandidates();
      void runComparison();
    } catch (e) {
      alert(e instanceof Error ? e.message : "Approval failed");
    } finally {
      setActionBusyJobId(null);
    }
  }

  // Quick Verify Handler
  async function handleVerify(jid: string) {
    setActionBusyJobId(jid);
    try {
      await api.verify(jid);
      await loadCandidates();
      void runComparison();
    } catch (e) {
      alert(e instanceof Error ? e.message : "Verification failed");
    } finally {
      setActionBusyJobId(null);
    }
  }

  return (
    <div className="page">
      <div className="page-heading">
        <div>
          <div className="eyebrow">AI-AGNOSTIC EVALUATION LAB // MULTI-MODEL BENCHMARK</div>
          <h1>Patch Comparison Lab</h1>
          <p>
            Submit and benchmark candidate security patches authored by Claude, Cursor, GitHub Copilot, DeepSeek, or
            manual development. Evaluates patches under identical pinned source revisions, strict file policies,
            isolated container test suites, and factual technical reporting—without arbitrary composite scores.
          </p>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <button
            className="button button-lime"
            onClick={() => setShowIntakeForm(!showIntakeForm)}
          >
            <PlusCircle size={15} style={{ marginRight: 6 }} />
            {showIntakeForm ? "Close Intake Form" : "Submit Candidate Patch"}
          </button>
        </div>
      </div>

      {/* Intake Modal / Expansion Panel */}
      {showIntakeForm && (
        <section
          className="panel"
          style={{
            marginBottom: 20,
            background: "linear-gradient(180deg, rgba(28, 18, 48, 0.95), rgba(16, 10, 26, 0.95))",
            border: "1px solid rgba(183, 243, 107, 0.35)",
            boxShadow: "0 6px 24px rgba(0,0,0,0.5)",
          }}
        >
          <div className="panel-heading">
            <div>
              <div className="eyebrow" style={{ color: "var(--signal-lime)" }}>EXTERNAL CANDIDATE SUBMISSION</div>
              <h2>
                <FileCode size={18} color="var(--signal-lime)" />
                Intake Candidate Patch
              </h2>
            </div>
          </div>

          <form onSubmit={handleIntakeSubmit}>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 14 }}>
              <div>
                <label style={{ display: "block", fontSize: 12, marginBottom: 4 }}>
                  Target Vulnerability Case
                </label>
                <select
                  value={selectedTargetJobId}
                  onChange={e => setSelectedTargetJobId(e.target.value)}
                  style={{ width: "100%", padding: "7px 10px", fontSize: 13 }}
                >
                  <option value="">Default BOLA Profile (bola-demo-v1)</option>
                  {jobs.map(j => (
                    <option key={j.job_id} value={j.job_id}>
                      {j.job_id} — {j.finding?.type || "BOLA"} ({j.status})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label style={{ display: "block", fontSize: 12, marginBottom: 4 }}>
                  Authoring Source / Tool
                </label>
                <div style={{ display: "flex", gap: 8 }}>
                  <select
                    value={authoringSource}
                    onChange={e => {
                      setAuthoringSource(e.target.value);
                      if (e.target.value !== "Custom") setCustomAuthor("");
                    }}
                    style={{ flex: 1, padding: "7px 10px", fontSize: 13 }}
                  >
                    {PRESET_SOURCES.map(s => (
                      <option key={s} value={s}>{s}</option>
                    ))}
                    <option value="Custom">Custom Source Label...</option>
                  </select>
                  {authoringSource === "Custom" && (
                    <input
                      placeholder="e.g. Llama-3-70B, Custom Script"
                      value={customAuthor}
                      onChange={e => setCustomAuthor(e.target.value)}
                      style={{ flex: 1, padding: "7px 10px", fontSize: 13 }}
                      required
                    />
                  )}
                </div>
              </div>
            </div>

            <div style={{ marginBottom: 14 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                <label style={{ fontSize: 12 }}>
                  Unified Diff (`diff --git a/... b/...`)
                </label>
                <span style={{ fontSize: 11, color: "var(--lavender-muted)" }}>
                  Must use UNIX newlines (\\n). Binary patches and CRLF are strictly rejected.
                </span>
              </div>
              <textarea
                value={patchText}
                onChange={e => setPatchText(e.target.value)}
                rows={8}
                style={{
                  width: "100%",
                  fontFamily: "monospace",
                  fontSize: 12,
                  padding: 10,
                  borderRadius: 4,
                  background: "rgba(0,0,0,0.5)",
                  color: "#e2e8f0",
                  boxSizing: "border-box",
                }}
                required
              />
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 16 }}>
              <div>
                <label style={{ display: "block", fontSize: 12, marginBottom: 4 }}>
                  Claimed Root Cause Analysis (Optional)
                </label>
                <input
                  value={rootCause}
                  onChange={e => setRootCause(e.target.value)}
                  style={{ width: "100%", padding: "7px 10px", fontSize: 13 }}
                />
              </div>
              <div>
                <label style={{ display: "block", fontSize: 12, marginBottom: 4 }}>
                  Remediation Explanation (Optional)
                </label>
                <input
                  value={explanation}
                  onChange={e => setExplanation(e.target.value)}
                  style={{ width: "100%", padding: "7px 10px", fontSize: 13 }}
                />
              </div>
            </div>

            <div style={{ background: "rgba(0,0,0,0.3)", padding: 10, borderRadius: 6, marginBottom: 14, fontSize: 12, color: "var(--lavender-muted)", display: "flex", alignItems: "center", gap: 8 }}>
              <ShieldCheck size={16} color="var(--signal-lime)" />
              <span>
                <strong>Zero Trust Enforcement:</strong> User-supplied model names and hashes are never trusted.
                Authoritative SHA-256 hashes and target source revisions are computed strictly on the backend.
                Every patch must pass policy and require human review.
              </span>
            </div>

            {intakeError && (
              <div className="error-banner" style={{ marginBottom: 14 }}>
                <AlertTriangle size={15} /> {intakeError}
              </div>
            )}
            {intakeSuccess && (
              <div style={{ padding: "8px 12px", background: "rgba(34,197,94,0.15)", border: "1px solid rgba(34,197,94,0.3)", borderRadius: 6, color: "#4ade80", fontSize: 13, marginBottom: 14 }}>
                <CheckCircle2 size={15} style={{ display: "inline", verticalAlign: "middle", marginRight: 6 }} />
                {intakeSuccess}
              </div>
            )}

            <div style={{ display: "flex", gap: 10 }}>
              <button
                type="submit"
                className="button button-lime"
                disabled={intakeBusy || !patchText.trim()}
              >
                {intakeBusy ? "Validating & Submitting…" : "Intake Candidate Patch"}
              </button>
              <button
                type="button"
                className="button button-secondary"
                onClick={() => setShowIntakeForm(false)}
              >
                Cancel
              </button>
            </div>
          </form>
        </section>
      )}

      {/* Candidate Selector Strip */}
      <section className="panel" style={{ marginBottom: 20 }}>
        <div className="panel-heading">
          <div>
            <div className="eyebrow">LAB BENCHMARK SELECTION</div>
            <h2>
              <Layers size={18} />
              Candidate Patches ({candidates.length})
            </h2>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <button
              className="button button-ghost-sm"
              onClick={() => void loadCandidates()}
              disabled={loadingList}
            >
              <RefreshCw size={13} className={loadingList ? "spin" : ""} />
            </button>
            <span style={{ fontSize: 12, color: "var(--lavender-muted)" }}>
              Select 2 or more candidates to compare:
            </span>
          </div>
        </div>

        {loadingList ? (
          <p className="fine-print">Loading candidate patches…</p>
        ) : candidates.length === 0 ? (
          <div className="empty-state">
            <Sparkles size={24} style={{ marginBottom: 8 }} />
            <div>No external candidate patches submitted yet.</div>
            <p className="fine-print">Click &quot;Submit Candidate Patch&quot; above to intake fixes from Claude, Cursor, Copilot, or manual dev.</p>
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", fontSize: 12, borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.08)", color: "var(--lavender-muted)", textAlign: "left" }}>
                  <th style={{ padding: "8px 10px", width: 40 }}>Compare</th>
                  <th style={{ padding: "8px 10px" }}>Authoring Source</th>
                  <th style={{ padding: "8px 10px" }}>Job ID</th>
                  <th style={{ padding: "8px 10px" }}>Policy</th>
                  <th style={{ padding: "8px 10px" }}>Workflow Status</th>
                  <th style={{ padding: "8px 10px" }}>Patch Hash</th>
                  <th style={{ padding: "8px 10px" }}>Created</th>
                  <th style={{ padding: "8px 10px", textAlign: "right" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {candidates.map(c => {
                  const isChecked = selectedCandidateJobIds.includes(c.job_id);
                  const isBusy = actionBusyJobId === c.job_id;
                  return (
                    <tr
                      key={c.id}
                      style={{
                        borderBottom: "1px solid rgba(255,255,255,0.04)",
                        background: isChecked ? "rgba(183, 243, 107, 0.04)" : "transparent",
                      }}
                    >
                      <td style={{ padding: "8px 10px" }}>
                        <input
                          type="checkbox"
                          checked={isChecked}
                          onChange={() => toggleCandidateSelection(c.job_id)}
                          style={{ cursor: "pointer" }}
                        />
                      </td>
                      <td style={{ padding: "8px 10px" }}>
                        <strong style={{ color: "var(--signal-lime)", fontSize: 13 }}>
                          {c.authoring_source}
                        </strong>
                      </td>
                      <td style={{ padding: "8px 10px" }}>
                        <code>{c.job_id}</code>
                      </td>
                      <td style={{ padding: "8px 10px" }}>
                        <span
                          style={{
                            padding: "2px 6px",
                            borderRadius: 4,
                            fontSize: 11,
                            fontWeight: 700,
                            background: c.policy_status === "PASSED" ? "rgba(34,197,94,0.15)" : "rgba(239,68,68,0.15)",
                            color: c.policy_status === "PASSED" ? "#4ade80" : "#f87171",
                          }}
                        >
                          {c.policy_status}
                        </span>
                      </td>
                      <td style={{ padding: "8px 10px" }}>
                        <StatusBadge status={c.job_status} />
                      </td>
                      <td style={{ padding: "8px 10px" }}>
                        <code style={{ fontSize: 11 }}>{c.patch_hash.slice(0, 16)}…</code>
                      </td>
                      <td style={{ padding: "8px 10px", color: "var(--lavender-muted)", fontSize: 11 }}>
                        {new Date(c.created_at).toLocaleTimeString()}
                      </td>
                      <td style={{ padding: "8px 10px", textAlign: "right" }}>
                        <div style={{ display: "inline-flex", gap: 6 }}>
                          {c.job_status === "AWAITING_APPROVAL" && (
                            <button
                              className="button button-lime"
                              style={{ padding: "3px 8px", fontSize: 11 }}
                              disabled={isBusy}
                              onClick={() => handleApprove(c.job_id, c.patch_hash)}
                            >
                              Approve
                            </button>
                          )}
                          {(c.job_status === "VERIFYING" || c.job_status === "VERIFIED" || c.job_status === "VERIFICATION_FAILED") && (
                            <button
                              className="button button-secondary"
                              style={{ padding: "3px 8px", fontSize: 11 }}
                              disabled={isBusy || c.job_status === "VERIFIED"}
                              onClick={() => handleVerify(c.job_id)}
                            >
                              Verify
                            </button>
                          )}
                          <button
                            className="button button-ghost-sm"
                            style={{ padding: "3px 6px", fontSize: 11 }}
                            onClick={() => navigate(`/jobs/${encodeURIComponent(c.job_id)}`)}
                            title="Inspect Case"
                          >
                            <ExternalLink size={12} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Multi-Candidate Side-by-Side Comparison Matrix */}
      {comparisonReport && comparisonReport.candidates.length > 0 && (
        <section
          className="panel"
          style={{
            border: "1px solid rgba(183, 243, 107, 0.4)",
            background: "linear-gradient(180deg, rgba(25, 17, 40, 0.95), rgba(15, 10, 24, 0.95))",
            boxShadow: "0 4px 28px rgba(0,0,0,0.4)",
          }}
        >
          <div className="panel-heading" style={{ marginBottom: 16 }}>
            <div>
              <div className="eyebrow" style={{ color: "var(--signal-lime)" }}>
                FACTUAL TECHNICAL COMPARISON MATRIX
              </div>
              <h2>
                <GitCompare size={18} color="var(--signal-lime)" />
                Side-by-Side Candidate Evaluation ({comparisonReport.candidates.length} Patches)
              </h2>
            </div>
            <button
              className="button button-secondary"
              onClick={() => void runComparison()}
              disabled={loadingCompare}
            >
              <RefreshCw size={13} className={loadingCompare ? "spin" : ""} style={{ marginRight: 6 }} />
              Refresh Metrics
            </button>
          </div>

          {/* Normalization & Equivalence Banner */}
          <div
            style={{
              padding: "10px 14px",
              borderRadius: 6,
              marginBottom: 16,
              background: comparisonReport.source_revision_mismatch
                ? "rgba(239, 68, 68, 0.12)"
                : "rgba(34, 197, 94, 0.08)",
              border: `1px solid ${
                comparisonReport.source_revision_mismatch
                  ? "rgba(239, 68, 68, 0.3)"
                  : "rgba(34, 197, 94, 0.25)"
              }`,
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13 }}>
              {comparisonReport.source_revision_mismatch ? (
                <AlertTriangle size={16} color="#f87171" />
              ) : (
                <ShieldCheck size={16} color="#4ade80" />
              )}
              <strong style={{ color: comparisonReport.source_revision_mismatch ? "#f87171" : "#4ade80" }}>
                {comparisonReport.source_revision_mismatch
                  ? "Source Revision Discrepancy Detected"
                  : "Baseline Environment Normalized (Fair Comparison Guarantee)"}
              </strong>
            </div>
            <ul style={{ margin: "6px 0 0", paddingLeft: 20, fontSize: 12, color: "var(--lavender-muted)" }}>
              {comparisonReport.fair_comparison_notes.map((note, idx) => (
                <li key={idx}>{note}</li>
              ))}
            </ul>
          </div>

          {/* Side-by-Side Comparison Columns */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: `repeat(${comparisonReport.candidates.length}, minmax(280px, 1fr))`,
              gap: 16,
              overflowX: "auto",
              paddingBottom: 8,
            }}
          >
            {comparisonReport.candidates.map(c => {
              const isVerified = c.status === "VERIFIED";
              const isFailed = c.status === "VERIFICATION_FAILED";
              const isPolicyRejected = c.policy_status === "REJECTED";

              return (
                <div
                  key={c.job_id}
                  style={{
                    background: "rgba(0, 0, 0, 0.35)",
                    border: `1px solid ${
                      isVerified
                        ? "rgba(183, 243, 107, 0.4)"
                        : isFailed || isPolicyRejected
                        ? "rgba(239, 68, 68, 0.3)"
                        : "rgba(255, 255, 255, 0.08)"
                    }`,
                    borderRadius: 8,
                    padding: 14,
                    display: "flex",
                    flexDirection: "column",
                    gap: 12,
                  }}
                >
                  {/* Column Header */}
                  <div>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <span style={{ fontSize: 11, color: "var(--lavender-muted)" }}>CANDIDATE SOURCE</span>
                      <StatusBadge status={c.status} />
                    </div>
                    <strong style={{ fontSize: 16, color: "var(--signal-lime)", display: "block", marginTop: 2 }}>
                      {c.authoring_source}
                    </strong>
                    <div style={{ fontSize: 11, color: "var(--lavender-muted)" }}>
                      Job: <code>{c.job_id}</code>
                    </div>
                  </div>

                  {/* Policy Outcome */}
                  <div style={{ background: "rgba(0,0,0,0.25)", padding: 8, borderRadius: 5 }}>
                    <div style={{ fontSize: 11, color: "var(--lavender-muted)" }}>POLICY EVALUATION</div>
                    <div style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 2 }}>
                      {c.policy_status === "PASSED" ? (
                        <CheckCircle2 size={14} color="#4ade80" />
                      ) : (
                        <XCircle size={14} color="#f87171" />
                      )}
                      <span style={{ fontWeight: 700, fontSize: 12, color: c.policy_status === "PASSED" ? "#4ade80" : "#f87171" }}>
                        {c.policy_status}
                      </span>
                    </div>
                    {c.policy_reasons.length > 0 && (
                      <div style={{ fontSize: 11, color: "#fca5a5", marginTop: 4 }}>
                        {c.policy_reasons.join(", ")}
                      </div>
                    )}
                  </div>

                  {/* Diff & Size Stats */}
                  <div style={{ background: "rgba(0,0,0,0.25)", padding: 8, borderRadius: 5 }}>
                    <div style={{ fontSize: 11, color: "var(--lavender-muted)" }}>DIFF METRICS</div>
                    <div style={{ fontSize: 12, marginTop: 2 }}>
                      <span>Size: <strong>{c.patch_size_bytes} B</strong></span> &bull;{" "}
                      <span style={{ color: "#4ade80" }}>+{c.additions}</span>{" "}
                      <span style={{ color: "#f87171" }}>-{c.deletions}</span>
                    </div>
                    <div style={{ fontSize: 11, color: "var(--lavender-muted)", marginTop: 2 }}>
                      Files: <code>{c.files_changed.join(", ") || "none"}</code>
                    </div>
                  </div>

                  {/* Human Approval Status */}
                  <div style={{ background: "rgba(0,0,0,0.25)", padding: 8, borderRadius: 5 }}>
                    <div style={{ fontSize: 11, color: "var(--lavender-muted)" }}>HUMAN APPROVAL BINDING</div>
                    <strong style={{ fontSize: 12, color: c.approval_status === "APPROVED" ? "#4ade80" : "#fbbf24" }}>
                      {c.approval_status}
                    </strong>
                    {c.approved_by && (
                      <div style={{ fontSize: 11, color: "var(--lavender-muted)", marginTop: 2 }}>
                        By: {c.approved_by}
                      </div>
                    )}
                  </div>

                  {/* Isolated Test Outcomes */}
                  <div style={{ background: "rgba(0,0,0,0.25)", padding: 8, borderRadius: 5 }}>
                    <div style={{ fontSize: 11, color: "var(--lavender-muted)" }}>PROTECTED TEST SUITE</div>
                    {c.tests_total != null ? (
                      <div>
                        <div style={{ fontSize: 13, fontWeight: 700, marginTop: 2 }}>
                          <span style={{ color: "#4ade80" }}>{c.tests_passed} passed</span> / {c.tests_total} total
                        </div>
                        <div style={{ fontSize: 11, color: "var(--lavender-muted)", marginTop: 2 }}>
                          Duration: {c.duration_ms}ms &bull; Suite: <code>{c.test_suite_id}</code>
                        </div>
                      </div>
                    ) : (
                      <div style={{ fontSize: 11, color: "var(--lavender-muted)", fontStyle: "italic", marginTop: 2 }}>
                        Not verified yet
                      </div>
                    )}
                  </div>

                  {/* Adversarial Red Team Evaluation */}
                  <div style={{ background: "rgba(0,0,0,0.25)", padding: 8, borderRadius: 5 }}>
                    <div style={{ fontSize: 11, color: "var(--lavender-muted)" }}>ADVERSARIAL SECURITY</div>
                    {c.adversarial_summary ? (
                      <div>
                        <div style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 2 }}>
                          {c.adversarial_mitigated ? (
                            <ShieldCheck size={14} color="#4ade80" />
                          ) : (
                            <XCircle size={14} color="#f87171" />
                          )}
                          <span style={{ fontSize: 12, fontWeight: 700, color: c.adversarial_mitigated ? "#4ade80" : "#f87171" }}>
                            {c.adversarial_mitigated ? "VULNERABILITY MITIGATED" : "MITIGATION FAILED"}
                          </span>
                        </div>
                        <div style={{ fontSize: 11, color: "var(--lavender-muted)", marginTop: 4 }}>
                          Attacks: {c.adversarial_summary.attack_scenarios_passed}/{c.adversarial_summary.attack_scenarios_attempted} passed
                        </div>
                        <div style={{ fontSize: 11, color: "var(--lavender-muted)" }}>
                          Regressions: {c.adversarial_summary.regression_scenarios_passed}/{c.adversarial_summary.regression_scenarios_total} passed
                        </div>
                      </div>
                    ) : (
                      <div style={{ fontSize: 11, color: "var(--lavender-muted)", fontStyle: "italic", marginTop: 2 }}>
                        Awaiting execution
                      </div>
                    )}
                  </div>

                  {/* Cryptographic Attestation */}
                  <div style={{ background: "rgba(0,0,0,0.25)", padding: 8, borderRadius: 5 }}>
                    <div style={{ fontSize: 11, color: "var(--lavender-muted)" }}>EVIDENCE ATTESTATION</div>
                    {c.evidence_integrity ? (
                      <div style={{ fontSize: 11 }}>
                        <span style={{ color: "#4ade80", fontWeight: 600 }}>
                          <Lock size={12} style={{ display: "inline", marginRight: 4 }} />
                          Ed25519 Signed ({c.evidence_integrity.key_id})
                        </span>
                        <div style={{ color: "var(--lavender-muted)", marginTop: 2 }}>
                          Digest: <code>{c.evidence_integrity.canonical_digest.slice(0, 16)}…</code>
                        </div>
                      </div>
                    ) : (
                      <div style={{ fontSize: 11, color: "var(--lavender-muted)", fontStyle: "italic", marginTop: 2 }}>
                        No attestation recorded yet
                      </div>
                    )}
                  </div>

                  {/* Quick Action Footer */}
                  <div style={{ marginTop: "auto", paddingTop: 8, borderTop: "1px solid rgba(255,255,255,0.06)", display: "flex", justifyContent: "space-between" }}>
                    <button
                      className="button button-ghost-sm"
                      onClick={() => navigate(`/jobs/${encodeURIComponent(c.job_id)}`)}
                      style={{ fontSize: 11 }}
                    >
                      Inspect Details &rarr;
                    </button>
                    {c.status === "AWAITING_APPROVAL" && (
                      <button
                        className="button button-lime"
                        style={{ padding: "4px 8px", fontSize: 11 }}
                        onClick={() => handleApprove(c.job_id, c.patch_hash)}
                      >
                        Approve
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Unexplained Composite Score Disclaimer */}
          <div
            style={{
              marginTop: 16,
              padding: "10px 14px",
              borderRadius: 6,
              background: "rgba(0,0,0,0.3)",
              fontSize: 12,
              color: "var(--lavender-muted)",
              display: "flex",
              alignItems: "center",
              gap: 8,
              borderTop: "1px solid rgba(255,255,255,0.06)",
            }}
          >
            <Info size={16} color="var(--signal-lime)" />
            <span>
              <strong>Scientific &amp; Objective Policy:</strong> {comparisonReport.disclaimer} Each candidate&apos;s
              technical merits, test outcomes, and regression boundaries are presented transparently for operator review.
            </span>
          </div>
        </section>
      )}

      {/* Unsupported Formats & Rules Checklist */}
      <section className="panel evidence-checklist" style={{ marginTop: 20 }}>
        <div className="eyebrow">LAB INTAKE CONTRACT</div>
        <h2>Patch Intake Requirements &amp; Format Constraints</h2>
        <div className="checklist-grid">
          <div>
            <span>01</span>
            <strong>Standard Git Unified Diff</strong>
            <small>Must begin with `diff --git a/... b/...` and contain valid hunk headers.</small>
          </div>
          <div>
            <span>02</span>
            <strong>UNIX Line Endings Only</strong>
            <small>Windows CRLF (`\r\n`) and embedded null bytes are rejected at intake.</small>
          </div>
          <div>
            <span>03</span>
            <strong>Zero Prohibited Git Modes</strong>
            <small>Binary patches, file renames, creations, and deletions are strictly forbidden.</small>
          </div>
          <div>
            <span>04</span>
            <strong>Protected File Protection</strong>
            <small>Patches modifying tests, Dockerfiles, or runner scripts fail policy immediately.</small>
          </div>
          <div>
            <span>05</span>
            <strong>Recomputed SHA-256 Digest</strong>
            <small>Backend recomputes exact SHA-256 over raw diff bytes; client hashes are ignored.</small>
          </div>
          <div>
            <span>06</span>
            <strong>Mandatory Human Approval</strong>
            <small>No candidate patch bypasses operator approval regardless of claimed origin.</small>
          </div>
        </div>
      </section>
    </div>
  );
}
