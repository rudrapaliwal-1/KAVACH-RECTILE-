import { useEffect, useState, type FormEvent } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { Activity, RefreshCw, Search, ArrowUpRight, Database, Radio } from "lucide-react";
import { api, unwrapList } from "../api/jobs";
import type { Job, WorkflowEvent } from "../api/types";
import ActivityTimeline from "../components/ActivityTimeline";
import StatusBadge from "../components/StatusBadge";
import { request } from "../api/client";

export default function ActivityPage() {
  const location = useLocation();
  const navigate = useNavigate();
  const queryJobId = new URLSearchParams(location.search).get("jobId") || "";

  const [jobs, setJobs] = useState<Job[]>([]);
  const [jobsLoading, setJobsLoading] = useState(true);
  const [selectedJobId, setSelectedJobId] = useState<string>(queryJobId);
  const [jobInput, setJobInput] = useState<string>(queryJobId);

  const [events, setEvents] = useState<WorkflowEvent[]>([]);
  const [eventsLoading, setEventsLoading] = useState(false);
  const [eventsError, setEventsError] = useState("");

  const [localEvents, setLocalEvents] = useState<{ id: string; project_name: string; event_type: string; reference_id: string; status: string; created_at: string }[]>([]);
  const [localError, setLocalError] = useState("");

  const [observability, setObservability] = useState<{ configured: boolean; hosted_delivery_verified: boolean; trace_reference: string | null } | null>(null);

  const [scans, setScans] = useState<{ id: string; project_name: string; status: string; created_at: string; finding_count: number }[]>([]);
  const [scanError, setScanError] = useState("");

  // Load user jobs
  async function loadJobs() {
    setJobsLoading(true);
    try {
      const rows = await api.jobs(50, 0);
      setJobs(rows);
      if (!selectedJobId && rows.length > 0) {
        setSelectedJobId(rows[0].job_id);
        setJobInput(rows[0].job_id);
      }
    } catch {
      // Continue even if jobs empty
    } finally {
      setJobsLoading(false);
    }
  }

  // Load events for a specific job ID
  async function loadJobEvents(id: string) {
    if (!id.trim()) return;
    setEventsLoading(true);
    setEventsError("");
    try {
      const data = await api.events(id.trim());
      setEvents(unwrapList(data, "events"));
    } catch (err) {
      setEventsError(err instanceof Error ? err.message : `Unable to load events for job ${id}`);
      setEvents([]);
    } finally {
      setEventsLoading(false);
    }
  }

  useEffect(() => {
    void loadJobs();
    request<typeof localEvents>("/api/security-activity")
      .then(setLocalEvents)
      .catch(e => setLocalError(e instanceof Error ? e.message : "Activity unavailable"));
    request<typeof observability>("/api/observability/status")
      .then(setObservability)
      .catch(() => setObservability(null));
    request<typeof scans>("/api/scans")
      .then(setScans)
      .catch(e => setScanError(e instanceof Error ? e.message : "Scan activity unavailable"));
  }, []);

  useEffect(() => {
    if (queryJobId) {
      setSelectedJobId(queryJobId);
      setJobInput(queryJobId);
      void loadJobEvents(queryJobId);
    } else if (selectedJobId) {
      void loadJobEvents(selectedJobId);
    }
  }, [queryJobId, selectedJobId]);

  function handleSelectJob(id: string) {
    setSelectedJobId(id);
    setJobInput(id);
    navigate(`/activity?jobId=${encodeURIComponent(id)}`, { replace: true });
    void loadJobEvents(id);
  }

  function handleCustomQuery(e: FormEvent) {
    e.preventDefault();
    if (!jobInput.trim()) return;
    setSelectedJobId(jobInput.trim());
    navigate(`/activity?jobId=${encodeURIComponent(jobInput.trim())}`, { replace: true });
    void loadJobEvents(jobInput.trim());
  }

  const selectedJob = jobs.find(j => j.job_id === selectedJobId);

  return (
    <div className="page">
      <div className="page-heading">
        <div>
          <div className="eyebrow">INTELLIGENCE // AUDIT TRAIL</div>
          <h1>Agent Activity</h1>
          <p>Inspect backend-recorded workflow transitions, patch hashes, and autonomous retry cycles.</p>
        </div>
      </div>

      {/* Observability Telemetry Banner */}
      <section className="panel" style={{ background: "rgba(23, 16, 37, 0.6)", borderColor: "rgba(183, 243, 107, 0.2)" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 12 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <Radio size={20} color="var(--signal-lime)" />
            <div>
              <strong>Neatlogs Observability Status</strong>
              <div style={{ fontSize: 13, color: "var(--lavender-muted)" }}>
                {observability ? (
                  observability.configured ? (
                    <span style={{ color: "var(--signal-lime)" }}>● Configured & Active</span>
                  ) : (
                    <span>○ Not configured (Local audit persistence active)</span>
                  )
                ) : (
                  "Querying telemetry engine…"
                )}
                {observability?.hosted_delivery_verified && " · Hosted delivery verified"}
                {observability?.trace_reference && (
                  <span> · Trace: <code>{observability.trace_reference}</code></span>
                )}
              </div>
            </div>
          </div>
          <div style={{ fontSize: 12, color: "var(--lavender-muted)", display: "flex", alignItems: "center", gap: 6 }}>
            <Database size={14} /> Local audit-log events are authoritative and persisted in SQLite.
          </div>
        </div>
      </section>

      {/* Job Selection & Event Timeline */}
      <div style={{ display: "grid", gridTemplateColumns: "340px 1fr", gap: 20, alignItems: "start" }}>
        {/* Left Column: Job Selector */}
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <section className="panel">
            <div className="panel-heading">
              <div>
                <div className="eyebrow">SELECT WORKFLOW</div>
                <h2>Remediation Jobs</h2>
              </div>
              <button
                className="button button-ghost-sm"
                onClick={() => void loadJobs()}
                disabled={jobsLoading}
                title="Refresh jobs"
              >
                <RefreshCw size={13} className={jobsLoading ? "spin" : ""} />
              </button>
            </div>

            <form onSubmit={handleCustomQuery} style={{ marginBottom: 14 }}>
              <div style={{ display: "flex", gap: 6 }}>
                <input
                  value={jobInput}
                  onChange={e => setJobInput(e.target.value)}
                  placeholder="Query Job ID…"
                  style={{ flex: 1, padding: "6px 10px", fontSize: 13 }}
                />
                <button
                  type="submit"
                  className="button button-lime"
                  style={{ padding: "6px 10px" }}
                  disabled={!jobInput.trim()}
                >
                  <Search size={14} />
                </button>
              </div>
            </form>

            {jobsLoading && <p className="fine-print">Loading jobs…</p>}
            {!jobsLoading && jobs.length === 0 && (
              <p className="fine-print">No jobs found. Upload a repository or launch a BOLA remediation job.</p>
            )}

            <div style={{ display: "flex", flexDirection: "column", gap: 8, maxHeight: 480, overflowY: "auto" }}>
              {jobs.map(job => (
                <div
                  key={job.job_id}
                  onClick={() => handleSelectJob(job.job_id)}
                  style={{
                    padding: "10px 12px",
                    borderRadius: 6,
                    cursor: "pointer",
                    border: "1px solid",
                    borderColor: selectedJobId === job.job_id ? "var(--signal-lime)" : "rgba(183, 243, 107, 0.1)",
                    background: selectedJobId === job.job_id ? "rgba(183, 243, 107, 0.08)" : "rgba(41, 33, 60, 0.3)",
                    transition: "all 0.15s ease",
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                    <code style={{ fontSize: 11, color: "var(--signal-lime)" }}>{job.job_id}</code>
                    <StatusBadge status={job.status} />
                  </div>
                  <div style={{ fontSize: 13, fontWeight: 600, color: "var(--warm-paper)" }}>
                    {job.finding?.type?.replaceAll("_", " ") || job.summary || "Security finding"}
                  </div>
                  <div style={{ fontSize: 11, color: "var(--lavender-muted)", marginTop: 4 }}>
                    {job.created_at ? new Date(job.created_at).toLocaleString() : "Date unavailable"}
                  </div>
                </div>
              ))}
            </div>
          </section>
        </div>

        {/* Right Column: Workflow Timeline for Selected Job */}
        <section className="panel">
          <div className="panel-heading">
            <div>
              <div className="eyebrow">PERSISTED EVENT TIMELINE</div>
              <h2>
                <Activity size={18} />
                {selectedJobId ? `Job ${selectedJobId}` : "Select a Job"}
              </h2>
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              {selectedJobId && (
                <Link
                  className="button button-orbit"
                  style={{ padding: "6px 12px", fontSize: 12 }}
                  to={`/jobs/${encodeURIComponent(selectedJobId)}`}
                >
                  Open Investigation <ArrowUpRight size={13} />
                </Link>
              )}
              {selectedJobId && (
                <button
                  className="button button-secondary"
                  style={{ padding: "6px 12px", fontSize: 12 }}
                  onClick={() => void loadJobEvents(selectedJobId)}
                  disabled={eventsLoading}
                >
                  <RefreshCw size={13} className={eventsLoading ? "spin" : ""} /> Refresh
                </button>
              )}
            </div>
          </div>

          {selectedJob && (
            <div style={{ background: "rgba(41, 33, 60, 0.4)", padding: "10px 14px", borderRadius: 6, marginBottom: 16, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <strong>Current State:</strong> <StatusBadge status={selectedJob.status} />
                {selectedJob.finding?.file_path && (
                  <span style={{ marginLeft: 12, fontSize: 13, color: "var(--lavender-muted)" }}>
                    Target: <code>{selectedJob.finding.file_path}</code>
                  </span>
                )}
              </div>
              {selectedJob.attempt != null && (
                <span className="badge info">Attempt {selectedJob.attempt}</span>
              )}
            </div>
          )}

          {eventsError && (
            <div className="error-banner" role="alert" style={{ marginBottom: 14 }}>
              {eventsError}
            </div>
          )}

          {eventsLoading && (
            <div className="empty-state">
              <RefreshCw size={24} className="spin" style={{ marginBottom: 10 }} />
              <div>Fetching authoritative backend events for <code>{selectedJobId}</code>…</div>
            </div>
          )}

          {!eventsLoading && !eventsError && events.length > 0 && (
            <ActivityTimeline events={events} />
          )}

          {!eventsLoading && !eventsError && !events.length && selectedJobId && (
            <div className="empty-state">
              No workflow events were returned for job <code>{selectedJobId}</code>.
            </div>
          )}

          {!selectedJobId && (
            <div className="empty-state">
              Select a job from the left panel or enter a Job ID above to inspect its event timeline.
            </div>
          )}
        </section>
      </div>

      {/* General Analysis & Scan Activity */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, marginTop: 20 }}>
        <section className="panel">
          <div className="panel-heading">
            <h2>System Lifecycle Events</h2>
          </div>
          {localError && <p role="alert">{localError}</p>}
          {localEvents.length ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Project</th>
                    <th>Event</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {localEvents.slice(0, 10).map(event => (
                    <tr key={event.id}>
                      <td className="date-cell">{new Date(event.created_at).toLocaleString()}</td>
                      <td>{event.project_name}</td>
                      <td><code>{event.event_type}</code></td>
                      <td><span className="badge info">{event.status}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="empty-hint">No generalized lifecycle events recorded yet.</p>
          )}
        </section>

        <section className="panel">
          <div className="panel-heading">
            <h2>Recent Security Scans</h2>
          </div>
          {scanError && <p role="alert">{scanError}</p>}
          {scans.length ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Date</th>
                    <th>Project</th>
                    <th>Status</th>
                    <th>Findings</th>
                  </tr>
                </thead>
                <tbody>
                  {scans.slice(0, 10).map(scan => (
                    <tr key={scan.id}>
                      <td className="date-cell">{new Date(scan.created_at).toLocaleString()}</td>
                      <td>{scan.project_name}</td>
                      <td><span className="badge success">{scan.status}</span></td>
                      <td><strong style={{ color: "var(--signal-lime)" }}>{scan.finding_count}</strong> findings</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="empty-hint">No scan events recorded yet.</p>
          )}
        </section>
      </div>

      <section className="panel event-types" style={{ marginTop: 20 }}>
        <div className="eyebrow">WORKFLOW STATE MACHINE SPECIFICATION</div>
        <h2>Standard Lifecycle States</h2>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginTop: 10 }}>
          {[
            "FINDING_RECEIVED",
            "PLANNING",
            "AWAITING_APPROVAL",
            "VERIFYING",
            "VERIFIED",
            "VERIFICATION_FAILED",
            "POLICY_REJECTED",
            "USER_REJECTED",
            "RETRY_EXHAUSTED",
            "EXECUTION_ERROR",
          ].map(state => (
            <StatusBadge key={state} status={state} />
          ))}
        </div>
      </section>
    </div>
  );
}