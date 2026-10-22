import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { RefreshCw, Search, ChevronLeft, ChevronRight } from "lucide-react";
import { request } from "../api/client";
import { api } from "../api/jobs";
import { useJobs } from "../hooks/useJobs";
import FindingsTable from "../components/FindingsTable";

type Finding = {
  id: string; scan_id: string; project_id: string; project_name: string; category: string;
  severity: string; confidence: string; file_path: string; line_start: number; line_end: number;
  evidence: string; explanation: string; recommendation: string; detection_source: string; validation_status: string;
};
type ScanPatch = {
  id: string; finding_id: string; diff: string; patch_hash: string; root_cause: string;
  explanation: string; approval_status: string; verification_status: string;
  verification?: { status: string; checks: Record<string, boolean>; reason: string } | null;
};
type Preview = { files: { path: string; bytes_to_send_max: number }[]; message: string };
type Review = { items: { finding_id: string; assessment: string; explanation: string; recommendation: string }[]; notice: string };

export default function Findings() {
  const location = useLocation();
  const { jobs, loading: jobsLoading, error: jobsError, refresh: refreshJobs } = useJobs();
  const [rows, setRows] = useState<Finding[]>([]);
  const [aiReady, setAiReady] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState(new URLSearchParams(window.location.search).get("search") || "");
  useEffect(() => { setFilter(new URLSearchParams(location.search).get("search") || ""); }, [location.search]);

  const [severity, setSeverity] = useState("");
  const [category, setCategory] = useState("");
  const [status, setStatus] = useState("");
  const [selected, setSelected] = useState<Finding | null>(null);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [patch, setPatch] = useState<ScanPatch | null>(null);
  const [patchBusy, setPatchBusy] = useState(false);
  const [consent, setConsent] = useState(false);
  const [review, setReview] = useState<Review | null>(null);
  const [reviewBusy, setReviewBusy] = useState(false);

  // Pagination states
  const [findingsPage, setFindingsPage] = useState(1);
  const findingsPageSize = 8;
  const [jobsPage, setJobsPage] = useState(1);
  const jobsPageSize = 6;

  async function refresh() {
    setLoading(true);
    setError("");
    try {
      setRows(await request<Finding[]>("/api/scan-findings"));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load findings");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void refresh();
    request<{ configured: boolean }>("/api/ai/readiness")
      .then(value => setAiReady(value.configured))
      .catch(() => setAiReady(null));
  }, []);

  // Reset pagination on filter changes
  useEffect(() => {
    setFindingsPage(1);
    setJobsPage(1);
  }, [filter, severity, category, status]);

  const filtered = rows.filter(f =>
    (!severity || f.severity === severity) &&
    (!category || f.category === category) &&
    (!status || f.validation_status === status) &&
    `${f.id} ${f.category} ${f.file_path} ${f.project_name}`.toLowerCase().includes(filter.toLowerCase())
  );

  const jobFiltered = jobs.filter(j =>
    `${j.finding?.id || j.finding_id || ""} ${j.finding?.type || ""} ${j.finding?.file_path || ""} ${j.job_id}`
      .toLowerCase()
      .includes(filter.toLowerCase())
  );

  const totalFindingsPages = Math.ceil(filtered.length / findingsPageSize) || 1;
  const pagedFindings = filtered.slice((findingsPage - 1) * findingsPageSize, findingsPage * findingsPageSize);

  const totalJobsPages = Math.ceil(jobFiltered.length / jobsPageSize) || 1;
  const pagedJobs = jobFiltered.slice((jobsPage - 1) * jobsPageSize, jobsPage * jobsPageSize);

  async function showPreview(f: Finding) {
    setSelected(f);
    setPreview(null);
    setReview(null);
    setPatch(null);
    setConsent(false);
    setError("");
    try {
      const [p, history, priorReviews] = await Promise.all([
        request<Preview>(`/api/projects/${f.project_id}/ai-review/preview?scan_id=${encodeURIComponent(f.scan_id)}`),
        request<{ id: string }[]>(`/api/scan-findings/${f.id}/patches`),
        request<{ id: string; items: Review["items"] }[]>(`/api/scan-findings/${f.id}/reviews`),
      ]);
      setPreview(p);
      if (priorReviews.length) {
        setReview({ items: priorReviews[0].items, notice: "Saved advisory AI review; it does not establish exploitability." });
      }
      if (history.length) {
        setPatch(await request<ScanPatch>(`/api/scan-patches/${history[0].id}`));
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load finding details");
    }
  }

  async function generatePatch() {
    if (!selected || !consent || patchBusy) return;
    setPatchBusy(true);
    setError("");
    try {
      setPatch(await request<ScanPatch>(`/api/scan-findings/${selected.id}/patch`, {
        method: "POST",
        body: JSON.stringify({ consent: true, approved_file: selected.file_path }),
      }, 35000));
    } catch (e) {
      setError(e instanceof Error ? e.message : "AI patch unavailable");
    } finally {
      setPatchBusy(false);
    }
  }

  async function decidePatch(decision: "APPROVE" | "REJECT") {
    if (!patch) return;
    setPatchBusy(true);
    setError("");
    try {
      await request(`/api/scan-patches/${patch.id}/approval`, {
        method: "POST",
        body: JSON.stringify({ patch_hash: patch.patch_hash, decision }),
      });
      setPatch(await request<ScanPatch>(`/api/scan-patches/${patch.id}`));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Decision failed");
    } finally {
      setPatchBusy(false);
    }
  }

  async function verifyPatch() {
    if (!patch) return;
    setPatchBusy(true);
    setError("");
    try {
      await request(`/api/scan-patches/${patch.id}/verify`, { method: "POST" });
      setPatch(await request<ScanPatch>(`/api/scan-patches/${patch.id}`));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Check failed");
    } finally {
      setPatchBusy(false);
    }
  }

  async function remediateBola() {
    if (!selected || selected.category !== "BOLA_IDOR") return;
    setReviewBusy(true);
    setError("");
    try {
      const job = await api.createFinding({
        target_app_id: selected.project_id,
        finding: {
          id: "BOLA-001",
          type: "BROKEN_OBJECT_LEVEL_AUTHORIZATION",
          severity: selected.severity,
          file_path: selected.file_path,
          description: selected.explanation,
        },
      });
      window.location.assign(`/jobs/${encodeURIComponent(job.job_id)}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not start supported remediation");
      setReviewBusy(false);
    }
  }

  async function requestReview() {
    if (!selected || !preview || !consent) return;
    setReviewBusy(true);
    setError("");
    try {
      setReview(await request<Review>(`/api/projects/${selected.project_id}/ai-review`, {
        method: "POST",
        body: JSON.stringify({
          scan_id: selected.scan_id,
          approved_files: preview.files.map(f => f.path),
          consent: true,
        }),
      }, 35000));
    } catch (e) {
      setError(e instanceof Error ? e.message : "AI review unavailable");
    } finally {
      setReviewBusy(false);
    }
  }

  return (
    <div className="page">
      <div className="page-heading">
        <div>
          <div className="eyebrow">SECURITY ANALYSIS</div>
          <h1>Security findings</h1>
          <p>Static scan matches are potential findings. AI review is advisory and requires source-sharing consent.</p>
        </div>
        <Link className="button button-primary" to="/projects">Upload or scan project</Link>
      </div>

      {(error || jobsError) && <div className="error-banner" role="alert">{error || jobsError}</div>}

      {/* Potential Findings Table with Pagination */}
      <section className="panel table-panel">
        <div className="panel-heading">
          <div>
            <div className="eyebrow">STATIC SCANS</div>
            <h2>Potential findings <span className="subtle-count">{filtered.length}</span></h2>
          </div>
          <button className="button button-secondary" onClick={() => void refresh()} disabled={loading}>
            Refresh
          </button>
        </div>

        <div className="table-tools" style={{ padding: 16, flexWrap: "wrap" }}>
          <div className="input-search">
            <Search size={15} />
            <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter findings…" />
          </div>
          <select aria-label="Severity" value={severity} onChange={e => setSeverity(e.target.value)}>
            <option value="">All severities</option>
            {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(x => <option key={x}>{x}</option>)}
          </select>
          <select aria-label="Category" value={category} onChange={e => setCategory(e.target.value)}>
            <option value="">All categories</option>
            {[...new Set(rows.map(r => r.category))].map(x => <option key={x}>{x}</option>)}
          </select>
          <select aria-label="Validation status" value={status} onChange={e => setStatus(e.target.value)}>
            <option value="">All statuses</option>
            {[...new Set(rows.map(r => r.validation_status))].map(x => <option key={x}>{x}</option>)}
          </select>
        </div>

        {loading ? (
          <div className="loading-state"><RefreshCw size={17} className="spin" /> Loading findings…</div>
        ) : filtered.length ? (
          <>
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", textAlign: "left", borderSpacing: "0 10px" }}>
                <thead>
                  <tr>
                    <th>Project</th>
                    <th>Category</th>
                    <th>Severity</th>
                    <th>Confidence</th>
                    <th>Location</th>
                    <th>Status</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {pagedFindings.map(f => (
                    <tr key={f.id}>
                      <td>{f.project_name}</td>
                      <td>{f.category}</td>
                      <td>{f.severity}</td>
                      <td>{f.confidence}</td>
                      <td><code>{f.file_path}:{f.line_start}</code></td>
                      <td>{f.validation_status}</td>
                      <td>
                        <button className="button button-secondary" onClick={() => void showPreview(f)}>
                          Details
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Findings Pagination Controls */}
            {totalFindingsPages > 1 && (
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  padding: "12px 16px",
                  borderTop: "1px solid rgba(255,255,255,0.06)",
                  fontSize: "0.85rem",
                  color: "var(--text-muted, #889)",
                }}
              >
                <span>
                  Showing {(findingsPage - 1) * findingsPageSize + 1} to {Math.min(findingsPage * findingsPageSize, filtered.length)} of {filtered.length} findings
                </span>
                <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                  <button
                    className="button button-secondary"
                    disabled={findingsPage <= 1}
                    onClick={() => setFindingsPage(p => Math.max(1, p - 1))}
                    style={{ padding: "4px 8px" }}
                  >
                    <ChevronLeft size={14} /> Previous
                  </button>
                  <span style={{ padding: "0 6px" }}>Page {findingsPage} of {totalFindingsPages}</span>
                  <button
                    className="button button-secondary"
                    disabled={findingsPage >= totalFindingsPages}
                    onClick={() => setFindingsPage(p => Math.min(totalFindingsPages, p + 1))}
                    style={{ padding: "4px 8px" }}
                  >
                    Next <ChevronRight size={14} />
                  </button>
                </div>
              </div>
            )}
          </>
        ) : (
          <p style={{ padding: 16 }}>No matching static findings. Start a scan from Projects. No findings does not prove the source is safe.</p>
        )}
      </section>

      {/* Selected Finding Detail & AI Patch Section */}
      {selected && (
        <section className="panel" style={{ padding: 20 }}>
          <h2>{selected.category} · {selected.id}</h2>
          <p><strong>Project:</strong> {selected.project_name} · <strong>File:</strong> <code>{selected.file_path}:{selected.line_start}-{selected.line_end}</code></p>
          <p><strong>Evidence:</strong> {selected.evidence}</p>
          <p><strong>Explanation:</strong> {selected.explanation}</p>
          <p><strong>Recommendation:</strong> {selected.recommendation}</p>
          <p><strong>Source:</strong> {selected.detection_source} · <strong>Status:</strong> {selected.validation_status}</p>

          {selected.category === "BOLA_IDOR" && selected.file_path === "app/access.py" && (
            <p>
              <button className="button button-primary" disabled={reviewBusy} onClick={() => void remediateBola()}>
                Request protected BOLA remediation
              </button>
            </p>
          )}

          <h3>AI Security Analysis</h3>
          <p>Server integration: {aiReady === null ? "Checking..." : aiReady ? "Configured (live service availability may vary)" : "Not configured"}.</p>
          <p>Request contextual review of this scan. It cannot independently verify a vulnerability or a patch.</p>
          {!aiReady && (
            <div style={{ marginTop: 10, marginBottom: 12, padding: "10px 14px", background: "rgba(239, 68, 68, 0.12)", border: "1px solid rgba(239, 68, 68, 0.35)", borderRadius: 6, color: "#fca5a5", fontSize: "0.875rem" }}>
              <strong>Server integration not configured:</strong> Set <code>GEMINI_API_KEY</code> in the backend environment to enable external AI security reviews.
            </div>
          )}
          {error && (
            <div className="error-banner" style={{ marginTop: 10, marginBottom: 12 }} role="alert">
              {error}
            </div>
          )}

          {preview ? (
            <>
              <p>Source excerpts from these files will be sent to an external AI service:</p>
              <ul>{preview.files.map(f => <li key={f.path}><code>{f.path}</code> (up to {f.bytes_to_send_max} bytes)</li>)}</ul>
              <label>
                <input type="checkbox" checked={consent} onChange={e => setConsent(e.target.checked)} /> I authorize sharing the listed source excerpts for the AI review or selected Python patch draft.
              </label>
              <p>
                <button
                  className="button button-primary"
                  disabled={!consent || reviewBusy || !preview.files.length}
                  onClick={() => void requestReview()}
                >
                  {reviewBusy ? "Reviewing…" : "Request AI review"}
                </button>{" "}
                {selected.file_path.endsWith(".py") && !["BOLA_IDOR", "HARDCODED_SECRET"].includes(selected.category) && (
                  <button
                    className="button button-secondary"
                    disabled={!consent || patchBusy || !preview.files.some(f => f.path === selected.file_path)}
                    onClick={() => void generatePatch()}
                  >
                    {patchBusy ? "Working…" : "Generate Python patch draft"}
                  </button>
                )}
              </p>
            </>
          ) : (
            <p>Loading source preview…</p>
          )}

          {patch && (
            <div className="panel" style={{ padding: 16 }}>
              <h3>Advisory patch draft</h3>
              <p><strong>Hash:</strong> <code>{patch.patch_hash}</code> · <strong>Approval:</strong> {patch.approval_status} · <strong>Check:</strong> {patch.verification_status}</p>
              <p>{patch.root_cause} {patch.explanation}</p>
              <pre style={{ overflowX: "auto", maxHeight: 420 }}>{patch.diff}</pre>
              {patch.approval_status === "PENDING" && (
                <p>
                  <button className="button button-primary" disabled={patchBusy} onClick={() => void decidePatch("APPROVE")}>
                    Approve exact hash
                  </button>{" "}
                  <button className="button button-secondary" disabled={patchBusy} onClick={() => void decidePatch("REJECT")}>
                    Reject
                  </button>
                </p>
              )}
              {patch.approval_status === "APPROVE" && (
                <p>
                  <button className="button button-secondary" disabled={patchBusy} onClick={() => void verifyPatch()}>
                    Run syntax and static check
                  </button>
                </p>
              )}
              {patch.verification && (
                <p>
                  <strong>{patch.verification.status}:</strong> {patch.verification.reason} Syntax: {String(patch.verification.checks.python_syntax)}; selected pattern removed: {String(patch.verification.checks.selected_static_pattern_removed)}. Runtime tests were not run.
                </p>
              )}
              <p>No source file is modified. A syntax/static result cannot establish runtime safety.</p>
            </div>
          )}

          {review && (
            <div className="notice">
              <p>{review.notice}</p>
              {review.items.map(item => (
                <p key={item.finding_id}>
                  <strong>{item.assessment}:</strong> {item.explanation}<br />{item.recommendation}
                </p>
              ))}
            </div>
          )}
        </section>
      )}

      {/* Remediation Jobs Section with Pagination */}
      <section className="panel table-panel">
        <div className="panel-heading">
          <div>
            <div className="eyebrow">PROTECTED BOLA WORKFLOW</div>
            <h2>Remediation jobs <span className="subtle-count">{jobFiltered.length}</span></h2>
          </div>
          <button
            className="icon-button"
            onClick={() => void refreshJobs()}
            aria-label="Refresh jobs"
            disabled={jobsLoading}
          >
            <RefreshCw size={15} className={jobsLoading ? "spin" : ""} />
          </button>
        </div>

        {jobsLoading ? (
          <div className="loading-state">Loading jobs…</div>
        ) : (
          <>
            <FindingsTable jobs={pagedJobs} />
            {totalJobsPages > 1 && (
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  padding: "12px 16px",
                  borderTop: "1px solid rgba(255,255,255,0.06)",
                  fontSize: "0.85rem",
                  color: "var(--text-muted, #889)",
                }}
              >
                <span>
                  Showing {(jobsPage - 1) * jobsPageSize + 1} to {Math.min(jobsPage * jobsPageSize, jobFiltered.length)} of {jobFiltered.length} jobs
                </span>
                <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                  <button
                    className="button button-secondary"
                    disabled={jobsPage <= 1}
                    onClick={() => setJobsPage(p => Math.max(1, p - 1))}
                    style={{ padding: "4px 8px" }}
                  >
                    <ChevronLeft size={14} /> Previous
                  </button>
                  <span style={{ padding: "0 6px" }}>Page {jobsPage} of {totalJobsPages}</span>
                  <button
                    className="button button-secondary"
                    disabled={jobsPage >= totalJobsPages}
                    onClick={() => setJobsPage(p => Math.min(totalJobsPages, p + 1))}
                    style={{ padding: "4px 8px" }}
                  >
                    Next <ChevronRight size={14} />
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </section>
    </div>
  );
}
