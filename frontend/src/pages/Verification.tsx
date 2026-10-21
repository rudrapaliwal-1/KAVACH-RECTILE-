import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { RefreshCw, CheckCircle2, XCircle, AlertTriangle, ChevronDown, ChevronRight, ArrowUpRight, Clock, FileJson, ShieldCheck, FlaskConical, Gauge, Zap, Database } from "lucide-react";
import { request } from "../api/client";
import { api, verificationFromEvidence } from "../api/jobs";
import type { VerificationResult } from "../api/types";
import { useJobs } from "../hooks/useJobs";
import StatusBadge from "../components/StatusBadge";
import VibeCIPanel from "../components/VibeCIPanel";

interface PerformanceMetrics {
  total_runs: number;
  verification_duration: { median_ms: number; p95_ms: number; samples: number };
  ai_generation_latency: { median_ms: number; p95_ms: number; samples: number };
  test_suite_execution: { median_ms: number; p95_ms: number; samples: number };
  accuracy_and_reliability: {
    first_attempt_pass_rate_percent: number;
    retry_recovery_rate_percent: number;
    infrastructure_failure_rate_percent: number;
    evidence_integrity_failures: number;
    false_verified_adversarial_rate_percent: number;
    false_verified_adversarial_count: number;
  };
  caching: {
    overall_hit_rate_percent: number;
    total_cache_hits: number;
    total_cache_misses: number;
    layers: Record<string, { hits: number; misses: number; hit_rate_percent: number; current_size: number; max_size: number }>;
  };
  phases: Record<string, { median_ms: number; p95_ms: number; samples: number }>;
}

interface RegressionMemoryRecord {
  id: string;
  vulnerability_profile: string;
  source_context: string;
  failure_explanation: string;
  remediation_pattern: string;
  verification_limitations: string;
  created_at: string;
}

export default function Verification() {
  const { jobs, loading, error, refresh } = useJobs();
  const [runs, setRuns] = useState<Record<string, VerificationResult>>({});
  const [runsLoaded, setRunsLoaded] = useState(false);
  const [expandedJobId, setExpandedJobId] = useState<string | null>(null);

  const [patches, setPatches] = useState<{ id: string; finding_id: string; project_name: string; category: string; approval_status: string; verification_status: string }[]>([]);
  const [patchError, setPatchError] = useState("");
  const [metrics, setMetrics] = useState<PerformanceMetrics | null>(null);
  const [memories, setMemories] = useState<RegressionMemoryRecord[]>([]);

  async function refreshPatches() {
    try {
      setPatches(await request<typeof patches>("/api/scan-patches"));
      setPatchError("");
    } catch (e) {
      setPatchError(e instanceof Error ? e.message : "Could not load patch checks");
    }
  }

  async function refreshMetricsAndMemory() {
    try {
      const m = await request<PerformanceMetrics>("/api/observability/performance-metrics");
      setMetrics(m);
    } catch {
      // ignore
    }
    try {
      const memResp = await request<{ records: RegressionMemoryRecord[] }>("/api/observability/regression-memory");
      setMemories(memResp.records || []);
    } catch {
      // ignore
    }
  }

  useEffect(() => {
    let active = true;
    setRunsLoaded(false);
    Promise.all(
      jobs
        .filter(job => ["VERIFIED", "VERIFICATION_FAILED", "EXECUTION_ERROR"].includes(String(job.status)))
        .map(async job => {
          try {
            const ev = await api.evidence(job.job_id);
            const run = verificationFromEvidence(ev);
            return [job.job_id, run] as const;
          } catch {
            return [job.job_id, null] as const;
          }
        })
    ).then(values => {
      if (active) {
        setRuns(Object.fromEntries(values.filter(([, run]) => run !== null)) as Record<string, VerificationResult>);
        setRunsLoaded(true);
      }
    });
    return () => { active = false; };
  }, [jobs]);

  useEffect(() => {
    void refreshPatches();
    void refreshMetricsAndMemory();
  }, []);

  const verificationJobs = jobs.filter(j =>
    ["VERIFIED", "VERIFICATION_FAILED", "EXECUTION_ERROR", "VERIFYING", "AWAITING_APPROVAL"].includes(String(j.status))
  );

  return (
    <div className="page">
      <div className="page-heading">
        <div>
          <div className="eyebrow">INDEPENDENT VERIFIER // RESTRICTED RUNNER</div>
          <h1>Verification Matrix</h1>
          <p>
            Authoritative results from isolated container test execution. Verification outcomes are determined solely
            by protected test suites, never by the AI model or frontend claims.
          </p>
        </div>
        <button
          className="button button-secondary"
          onClick={() => { void refresh(); void refreshPatches(); void refreshMetricsAndMemory(); }}
          disabled={loading}
        >
          <RefreshCw size={15} className={loading ? "spin" : ""} /> Refresh
        </button>
      </div>

      {error && <div className="error-banner" role="alert">{error}</div>}

      {/* Main Verification Matrix */}
      <section className="panel">
        <div className="panel-heading">
          <div>
            <div className="eyebrow">DOCKER TEST SUITE RUNS</div>
            <h2>Protected Verification Outcomes ({verificationJobs.length})</h2>
          </div>
        </div>

        {loading ? (
          <p className="empty-hint">Loading verification jobs…</p>
        ) : verificationJobs.length === 0 ? (
          <div className="empty-state">
            No verification runs found. Start a remediation job on a supported BOLA repository, approve the generated patch, and execute verification.
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th style={{ width: 40 }} />
                  <th>Job ID / Target</th>
                  <th>Status</th>
                  <th>Test Suite ID</th>
                  <th>Tests (Passed/Total)</th>
                  <th>Duration</th>
                  <th>Patch Hash</th>
                  <th style={{ textAlign: "right" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {verificationJobs.map(job => {
                  const run = runs[job.job_id];
                  const isExpanded = expandedJobId === job.job_id;
                  const isCompleted = ["VERIFIED", "VERIFICATION_FAILED", "EXECUTION_ERROR"].includes(String(job.status));

                  return (
                    <>
                      <tr
                        key={job.job_id}
                        style={{ cursor: run?.test_results ? "pointer" : "default" }}
                        onClick={() => {
                          if (run?.test_results?.length) {
                            setExpandedJobId(isExpanded ? null : job.job_id);
                          }
                        }}
                      >
                        <td>
                          {run?.test_results?.length ? (
                            isExpanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />
                          ) : null}
                        </td>
                        <td>
                          <strong>{job.job_id}</strong>
                          <div style={{ fontSize: 11, color: "var(--lavender-muted)" }}>
                            {job.finding?.file_path || job.finding?.type || "BOLA Document Access"}
                          </div>
                        </td>
                        <td>
                          <StatusBadge status={job.status} />
                        </td>
                        <td>
                          <code style={{ fontSize: 12 }}>
                            {run?.test_suite_id || (isCompleted ? "bola-required-tests-v1" : "Pending")}
                          </code>
                        </td>
                        <td>
                          {run ? (
                            <span>
                              <strong style={{ color: "var(--signal-lime)" }}>{run.tests_passed ?? 0}</strong> / {run.tests_total ?? (Number(run.tests_passed || 0) + Number(run.tests_failed || 0))} passed
                              {Number(run.tests_failed || 0) > 0 && (
                                <span style={{ color: "var(--threat-coral)", marginLeft: 6 }}>
                                  ({run.tests_failed} failed)
                                </span>
                              )}
                            </span>
                          ) : isCompleted ? (
                            runsLoaded ? "No run record" : "Loading…"
                          ) : (
                            <span style={{ color: "var(--lavender-muted)" }}>Not yet executed</span>
                          )}
                        </td>
                        <td className="date-cell">
                          {run?.duration_ms != null ? (
                            <span><Clock size={12} style={{ display: "inline", marginRight: 4 }} />{(run.duration_ms / 1000).toFixed(2)}s</span>
                          ) : "—"}
                        </td>
                        <td>
                          {run?.patch_hash ? (
                            <code style={{ fontSize: 11 }}>{run.patch_hash.slice(0, 16)}…</code>
                          ) : job.patch_hash ? (
                            <code style={{ fontSize: 11 }}>{job.patch_hash.slice(0, 16)}…</code>
                          ) : "—"}
                        </td>
                        <td style={{ textAlign: "right" }} onClick={e => e.stopPropagation()}>
                          <div style={{ display: "inline-flex", gap: 6 }}>
                            <Link
                              className="button button-orbit"
                              style={{ padding: "4px 10px", fontSize: 12 }}
                              to={`/jobs/${encodeURIComponent(job.job_id)}`}
                            >
                              Investigation <ArrowUpRight size={12} />
                            </Link>
                            <Link
                              className="button button-ghost-sm"
                              style={{ padding: "4px 8px", fontSize: 12 }}
                              to={`/evidence?jobId=${encodeURIComponent(job.job_id)}`}
                              title="Inspect Evidence JSON"
                            >
                              <FileJson size={13} />
                            </Link>
                          </div>
                        </td>
                      </tr>

                      {/* Expandable Individual Test Results */}
                      {isExpanded && run?.test_results && run.test_results.length > 0 && (
                        <tr key={`${job.job_id}-details`} style={{ background: "rgba(41, 33, 60, 0.4)" }}>
                          <td colSpan={8} style={{ padding: "16px 24px" }}>
                            <div style={{ marginBottom: 8, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                              <strong>Individual Test Assertions ({run.test_results.length}):</strong>
                              {run.execution_error && (
                                <span style={{ color: "var(--threat-coral)", fontSize: 12 }}>
                                  Execution Error: {run.execution_error}
                                </span>
                              )}
                            </div>
                            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))", gap: 10 }}>
                              {run.test_results.map((test, idx) => (
                                <div
                                  key={idx}
                                  style={{
                                    padding: "8px 12px",
                                    borderRadius: 6,
                                    border: "1px solid",
                                    borderColor: test.outcome === "passed" ? "rgba(183, 243, 107, 0.3)" : "rgba(255, 122, 112, 0.3)",
                                    background: test.outcome === "passed" ? "rgba(183, 243, 107, 0.05)" : "rgba(255, 122, 112, 0.08)",
                                    display: "flex",
                                    alignItems: "center",
                                    justifyContent: "space-between",
                                  }}
                                >
                                  <div style={{ display: "flex", alignItems: "center", gap: 8, overflow: "hidden" }}>
                                    {test.outcome === "passed" ? (
                                      <CheckCircle2 size={15} color="var(--signal-lime)" />
                                    ) : (
                                      <XCircle size={15} color="var(--threat-coral)" />
                                    )}
                                    <span style={{ fontSize: 12, fontFamily: "var(--font-mono, monospace)" }}>
                                      {test.name}
                                    </span>
                                  </div>
                                  {test.duration_ms != null && (
                                    <span style={{ fontSize: 11, color: "var(--lavender-muted)" }}>
                                      {test.duration_ms}ms
                                    </span>
                                  )}
                                </div>
                              ))}
                            </div>

                            {/* Red Team Adversarial Report if present */}
                            {run?.adversarial_report && (
                              <div
                                style={{
                                  marginTop: 16,
                                  padding: "14px 18px",
                                  borderRadius: 8,
                                  background: "rgba(23, 16, 37, 0.9)",
                                  border: "1px solid rgba(183, 243, 107, 0.3)",
                                }}
                              >
                                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
                                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                                    <ShieldCheck size={16} color="var(--signal-lime)" />
                                    <strong>Red Team Adversarial Verification Matrix</strong>
                                    <span style={{ fontSize: 11, color: "var(--lavender-muted)", fontFamily: "monospace" }}>
                                      ({run.adversarial_report.protected_suite_version})
                                    </span>
                                  </div>
                                  <span
                                    style={{
                                      fontSize: 11,
                                      fontWeight: 600,
                                      padding: "2px 8px",
                                      borderRadius: 4,
                                      background: run.adversarial_report.vulnerability_mitigated ? "rgba(183, 243, 107, 0.15)" : "rgba(255, 122, 112, 0.15)",
                                      color: run.adversarial_report.vulnerability_mitigated ? "var(--signal-lime)" : "var(--threat-coral)",
                                    }}
                                  >
                                    {run.adversarial_report.vulnerability_mitigated ? "VULNERABILITY MITIGATED" : "MITIGATION FAILED"}
                                  </span>
                                </div>

                                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))", gap: 10, marginBottom: 12 }}>
                                  <div style={{ background: "rgba(0,0,0,0.3)", padding: "6px 10px", borderRadius: 4 }}>
                                    <div style={{ fontSize: 11, color: "var(--lavender-muted)" }}>Attack Vectors Tested</div>
                                    <strong style={{ fontSize: 13 }}>
                                      {run.adversarial_report.attack_scenarios_passed} / {run.adversarial_report.attack_scenarios_attempted} passed
                                    </strong>
                                  </div>
                                  <div style={{ background: "rgba(0,0,0,0.3)", padding: "6px 10px", borderRadius: 4 }}>
                                    <div style={{ fontSize: 11, color: "var(--lavender-muted)" }}>Regression Integrity</div>
                                    <strong style={{ fontSize: 13 }}>
                                      {run.adversarial_report.regression_scenarios_passed} / {run.adversarial_report.regression_scenarios_total} intact
                                    </strong>
                                  </div>
                                  <div style={{ background: "rgba(0,0,0,0.3)", padding: "6px 10px", borderRadius: 4 }}>
                                    <div style={{ fontSize: 11, color: "var(--lavender-muted)" }}>Baseline Proof</div>
                                    <strong style={{ fontSize: 13, color: "var(--signal-lime)" }}>
                                      {run.adversarial_report.vulnerability_reproduced_on_baseline ? "EXPLOITED ON BASELINE" : "UNPROVEN"}
                                    </strong>
                                  </div>
                                </div>

                                {run.adversarial_report.scenarios && run.adversarial_report.scenarios.length > 0 && (
                                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(260px, 1fr))", gap: 8, maxHeight: 180, overflowY: "auto" }}>
                                    {run.adversarial_report.scenarios.map((sc, sidx) => (
                                      <div
                                        key={sidx}
                                        style={{
                                          padding: "6px 8px",
                                          borderRadius: 4,
                                          background: "rgba(0,0,0,0.25)",
                                          border: `1px solid ${sc.execution_status === "passed" ? "rgba(183, 243, 107, 0.2)" : "rgba(255, 122, 112, 0.3)"}`,
                                          fontSize: 11,
                                        }}
                                      >
                                        <div style={{ display: "flex", justifyContent: "space-between" }}>
                                          <span style={{ fontFamily: "monospace", fontWeight: 600 }}>{sc.scenario_id}</span>
                                          <span style={{ color: sc.execution_status === "passed" ? "var(--signal-lime)" : "var(--threat-coral)" }}>
                                            {sc.execution_status.toUpperCase()}
                                          </span>
                                        </div>
                                        <div style={{ color: "var(--cream-soft)", marginTop: 2 }}>{sc.security_property}</div>
                                      </div>
                                    ))}
                                  </div>
                                )}

                                <p style={{ margin: "10px 0 0", fontSize: 11, color: "rgba(255,255,255,0.6)", fontStyle: "italic" }}>
                                  &bull; {run.adversarial_report.disclaimer}
                                </p>
                              </div>
                            )}

                            {/* Controlled Mutation Testing Report if present */}
                            {run?.mutation_report && (
                              <div
                                style={{
                                  marginTop: 16,
                                  padding: "14px 18px",
                                  borderRadius: 8,
                                  background: "rgba(23, 16, 37, 0.95)",
                                  border: "1px solid rgba(183, 243, 107, 0.4)",
                                }}
                              >
                                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
                                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                                    <FlaskConical size={16} color="var(--signal-lime)" />
                                    <strong>Test Quality &amp; Mutation Resilience Matrix</strong>
                                    <span style={{ fontSize: 11, color: "var(--lavender-muted)", fontFamily: "monospace" }}>
                                      ({run.mutation_report.test_suite_version})
                                    </span>
                                  </div>
                                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                                    <span
                                      style={{
                                        fontSize: 12,
                                        fontWeight: 700,
                                        fontFamily: "monospace",
                                        color: run.mutation_report.mutation_score >= 80 ? "var(--signal-lime)" : "#fbbf24",
                                      }}
                                    >
                                      {run.mutation_report.mutation_score.toFixed(1)}% Mutation Score
                                    </span>
                                  </div>
                                </div>

                                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))", gap: 8, marginBottom: 12 }}>
                                  <div style={{ background: "rgba(0,0,0,0.3)", padding: "6px 10px", borderRadius: 4 }}>
                                    <div style={{ fontSize: 11, color: "var(--lavender-muted)" }}>Valid Mutants</div>
                                    <strong style={{ fontSize: 13 }}>{run.mutation_report.valid_mutants} / {run.mutation_report.total_mutants}</strong>
                                  </div>
                                  <div style={{ background: "rgba(34,197,94,0.1)", padding: "6px 10px", borderRadius: 4 }}>
                                    <div style={{ fontSize: 11, color: "#4ade80" }}>Killed Mutants</div>
                                    <strong style={{ fontSize: 13, color: "#4ade80" }}>{run.mutation_report.killed_mutants}</strong>
                                  </div>
                                  <div style={{ background: run.mutation_report.surviving_mutants > 0 ? "rgba(239,68,68,0.1)" : "rgba(0,0,0,0.3)", padding: "6px 10px", borderRadius: 4 }}>
                                    <div style={{ fontSize: 11, color: run.mutation_report.surviving_mutants > 0 ? "#f87171" : "var(--lavender-muted)" }}>Surviving Mutants</div>
                                    <strong style={{ fontSize: 13, color: run.mutation_report.surviving_mutants > 0 ? "#f87171" : "#fff" }}>{run.mutation_report.surviving_mutants}</strong>
                                  </div>
                                  <div style={{ background: "rgba(0,0,0,0.3)", padding: "6px 10px", borderRadius: 4 }}>
                                    <div style={{ fontSize: 11, color: "var(--lavender-muted)" }}>Invalid (Excluded)</div>
                                    <strong style={{ fontSize: 13 }}>{run.mutation_report.invalid_mutants + run.mutation_report.inconclusive_mutants}</strong>
                                  </div>
                                  <div style={{ background: "rgba(0,0,0,0.3)", padding: "6px 10px", borderRadius: 4 }}>
                                    <div style={{ fontSize: 11, color: "var(--lavender-muted)" }}>Duration &amp; Formula</div>
                                    <span style={{ fontSize: 11, color: "var(--signal-lime)", fontFamily: "monospace" }}>{run.mutation_report.calculation_formula}</span>
                                  </div>
                                </div>

                                {run.mutation_report.surviving_mutant_weaknesses && run.mutation_report.surviving_mutant_weaknesses.length > 0 && (
                                  <div style={{ marginBottom: 10, padding: "8px 12px", borderRadius: 4, background: "rgba(239,68,68,0.12)", border: "1px solid rgba(239,68,68,0.3)" }}>
                                    <strong style={{ fontSize: 11, color: "#f87171", display: "block", marginBottom: 4 }}>
                                      Missing Security Scenarios / Test Weaknesses:
                                    </strong>
                                    <ul style={{ margin: 0, paddingLeft: 16, fontSize: 11, color: "#fecaca" }}>
                                      {run.mutation_report.surviving_mutant_weaknesses.map((w, idx) => (
                                        <li key={idx}>{w}</li>
                                      ))}
                                    </ul>
                                  </div>
                                )}

                                <p style={{ margin: "10px 0 0", fontSize: 11, color: "rgba(255,255,255,0.6)", fontStyle: "italic" }}>
                                  &bull; Test Quality Disclaimer: This score measures protected test-suite defect-detection rigor; it is NOT an overall application security rating.
                                </p>
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
        )}
      </section>
 
      {/* VibeCI Multi-Layer Verification & Pre-Flight Console */}
      <section className="panel" style={{ marginTop: 20 }}>
        <div className="panel-heading">
          <div>
            <div className="eyebrow">DEVELOPMENT VERIFICATION // LOCAL ENGINE</div>
            <h2>VibeCI Multi-Layer Preflight &amp; Verification</h2>
          </div>
        </div>
        <div style={{ padding: "18px 24px" }}>
          <VibeCIPanel />
        </div>
      </section>

      {/* Advisory Python Patch Checks */}
      <section className="panel" style={{ marginTop: 20 }}>
        <div className="panel-heading">
          <div>
            <div className="eyebrow">STATIC RECHECKS</div>
            <h2>Advisory Python Patch Checks</h2>
          </div>
          <button className="button button-ghost-sm" onClick={() => void refreshPatches()}>
            <RefreshCw size={13} />
          </button>
        </div>
        {patchError && <p role="alert" className="error-banner">{patchError}</p>}
        {patches.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Project</th>
                  <th>Category</th>
                  <th>Human Approval</th>
                  <th>Syntax / Static Check</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {patches.map(p => (
                  <tr key={p.id}>
                    <td><strong>{p.project_name}</strong></td>
                    <td>{p.category}</td>
                    <td>
                      <span className={`badge ${p.approval_status === "APPROVED" ? "success" : "muted"}`}>
                        {p.approval_status}
                      </span>
                    </td>
                    <td>
                      <span className={`badge ${p.verification_status === "VERIFIED" ? "success" : p.verification_status === "FAILED" ? "danger" : "info"}`}>
                        {p.verification_status}
                      </span>
                    </td>
                    <td>
                      <Link className="button button-ghost-sm" to={`/findings?search=${encodeURIComponent(p.finding_id)}`}>
                        View Finding
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="empty-hint">No advisory patch checks recorded yet.</p>
        )}
        <div style={{ marginTop: 12, fontSize: 12, color: "var(--lavender-muted)", display: "flex", alignItems: "center", gap: 6 }}>
          <AlertTriangle size={14} color="var(--orbit-violet)" />
          Python syntax and static rechecks can return FAILED or INCONCLUSIVE. They never establish a VERIFIED verdict without isolated protected tests.
        </div>
      </section>

      {/* Verification Performance & Safe Caching Telemetry */}
      <section className="panel" style={{ marginTop: 20 }}>
        <div className="panel-heading">
          <div>
            <div className="eyebrow">METRICS & SAFE OPTIMIZATION</div>
            <h2>Verification Engine Latency & Caching</h2>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span className="badge success" style={{ display: "flex", alignItems: "center", gap: 4 }}>
              <Zap size={13} />
              Cache Hit Rate: {metrics?.caching?.overall_hit_rate_percent ?? 0}%
            </span>
            <span className="badge info" style={{ display: "flex", alignItems: "center", gap: 4 }}>
              <Gauge size={13} />
              Runs: {metrics?.total_runs ?? 0}
            </span>
          </div>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))", gap: 14, marginTop: 14 }}>
          <div style={{ background: "rgba(22, 16, 36, 0.6)", padding: 14, borderRadius: 6, border: "1px solid rgba(183, 243, 107, 0.15)" }}>
            <div style={{ fontSize: 11, color: "var(--lavender-muted)", textTransform: "uppercase", letterSpacing: "0.05em" }}>Verification Duration</div>
            <div style={{ fontSize: 22, fontWeight: 700, color: "var(--signal-lime)", marginTop: 4 }}>
              {metrics?.verification_duration?.median_ms ? `${metrics.verification_duration.median_ms} ms` : "0 ms"}
            </div>
            <div style={{ fontSize: 11, color: "var(--lavender-muted)", marginTop: 2 }}>
              p95: {metrics?.verification_duration?.p95_ms ?? 0} ms ({metrics?.verification_duration?.samples ?? 0} samples)
            </div>
          </div>

          <div style={{ background: "rgba(22, 16, 36, 0.6)", padding: 14, borderRadius: 6, border: "1px solid rgba(183, 243, 107, 0.15)" }}>
            <div style={{ fontSize: 11, color: "var(--lavender-muted)", textTransform: "uppercase", letterSpacing: "0.05em" }}>First-Attempt Pass Rate</div>
            <div style={{ fontSize: 22, fontWeight: 700, color: "var(--signal-lime)", marginTop: 4 }}>
              {metrics?.accuracy_and_reliability?.first_attempt_pass_rate_percent ?? 0}%
            </div>
            <div style={{ fontSize: 11, color: "var(--lavender-muted)", marginTop: 2 }}>
              Retry Recovery: {metrics?.accuracy_and_reliability?.retry_recovery_rate_percent ?? 0}%
            </div>
          </div>

          <div style={{ background: "rgba(22, 16, 36, 0.6)", padding: 14, borderRadius: 6, border: "1px solid rgba(183, 243, 107, 0.15)" }}>
            <div style={{ fontSize: 11, color: "var(--lavender-muted)", textTransform: "uppercase", letterSpacing: "0.05em" }}>Test Suite Execution</div>
            <div style={{ fontSize: 22, fontWeight: 700, color: "var(--lavender)", marginTop: 4 }}>
              {metrics?.test_suite_execution?.median_ms ? `${metrics.test_suite_execution.median_ms} ms` : "0 ms"}
            </div>
            <div style={{ fontSize: 11, color: "var(--lavender-muted)", marginTop: 2 }}>
              p95: {metrics?.test_suite_execution?.p95_ms ?? 0} ms
            </div>
          </div>

          <div style={{ background: "rgba(22, 16, 36, 0.6)", padding: 14, borderRadius: 6, border: "1px solid rgba(183, 243, 107, 0.15)" }}>
            <div style={{ fontSize: 11, color: "var(--lavender-muted)", textTransform: "uppercase", letterSpacing: "0.05em" }}>Adversarial False Verified</div>
            <div style={{ fontSize: 22, fontWeight: 700, color: "#4ade80", marginTop: 4 }}>
              {metrics?.accuracy_and_reliability?.false_verified_adversarial_rate_percent ?? 0}%
            </div>
            <div style={{ fontSize: 11, color: "var(--lavender-muted)", marginTop: 2 }}>
              Strict Invariant: 0 False Positives
            </div>
          </div>
        </div>

        {/* Cache Layers Status */}
        <div style={{ marginTop: 18 }}>
          <h3 style={{ fontSize: 13, textTransform: "uppercase", letterSpacing: "0.05em", color: "var(--lavender-muted)", marginBottom: 8 }}>
            Safe Multi-Layer Caching (All keys bind 5-parameter composite hash)
          </h3>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 10 }}>
            {metrics?.caching?.layers && Object.entries(metrics.caching.layers).map(([layerName, layerStats]) => (
              <div key={layerName} style={{ padding: 10, background: "rgba(41, 33, 60, 0.2)", borderRadius: 4, border: "1px solid rgba(255, 255, 255, 0.05)" }}>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, fontWeight: 600 }}>
                  <span style={{ textTransform: "capitalize" }}>{layerName.replace(/_/g, " ")}</span>
                  <span style={{ color: "var(--signal-lime)" }}>{layerStats.hit_rate_percent}% Hit</span>
                </div>
                <div style={{ fontSize: 11, color: "var(--lavender-muted)", marginTop: 4 }}>
                  {layerStats.hits} hits / {layerStats.misses} misses ({layerStats.current_size}/{layerStats.max_size} entries)
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Advisory Regression Memory Bank */}
      <section className="panel" style={{ marginTop: 20 }}>
        <div className="panel-heading">
          <div>
            <div className="eyebrow">HISTORICAL KNOWLEDGE (BOUNDED)</div>
            <h2>Regression Memory & Failure Explanations ({memories.length})</h2>
          </div>
          <span className="badge muted" style={{ display: "flex", alignItems: "center", gap: 4 }}>
            <Database size={13} />
            Advisory Context Only
          </span>
        </div>
        <p className="fine-print" style={{ marginBottom: 12 }}>
          Historical failure patterns and known remediations assist patch generation without substituting for verification.
          Every candidate patch is independently tested against protected suites. No secrets, tokens, or raw source stored.
        </p>

        {memories.length === 0 ? (
          <p className="empty-hint">No regression memory records registered yet. New failure patterns are automatically recorded after failed verification runs.</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Vulnerability Profile</th>
                  <th>Source Context</th>
                  <th>Sanitized Failure Explanation</th>
                  <th>Known Remediation</th>
                  <th>Limitations</th>
                </tr>
              </thead>
              <tbody>
                {memories.map(mem => (
                  <tr key={mem.id}>
                    <td>
                      <span className="badge warning">{mem.vulnerability_profile}</span>
                    </td>
                    <td>
                      <code>{mem.source_context}</code>
                    </td>
                    <td style={{ maxWidth: 300 }}>
                      <div style={{ fontSize: 12, color: "var(--lavender)" }}>{mem.failure_explanation}</div>
                    </td>
                    <td style={{ maxWidth: 280 }}>
                      <div style={{ fontSize: 12, color: "var(--signal-lime)" }}>{mem.remediation_pattern}</div>
                    </td>
                    <td style={{ fontSize: 11, color: "var(--lavender-muted)" }}>
                      {mem.verification_limitations}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Architecture & Verification Guarantees */}
      <section className="panel" style={{ marginTop: 20 }}>
        <div className="eyebrow">SECURITY GUARANTEES</div>
        <h2>Verification Engine Architecture</h2>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 16, marginTop: 12 }}>
          <div style={{ background: "rgba(41, 33, 60, 0.3)", padding: 14, borderRadius: 6, border: "1px solid rgba(183, 243, 107, 0.15)" }}>
            <strong style={{ color: "var(--signal-lime)", display: "block", marginBottom: 6 }}>1. Exact-Patch-Hash Enforcement</strong>
            <p className="fine-print">Approval is cryptographically bound to <code>sha256(canonical_diff)</code> and source revision. Changed diffs instantly revoke approval.</p>
          </div>
          <div style={{ background: "rgba(41, 33, 60, 0.3)", padding: 14, borderRadius: 6, border: "1px solid rgba(183, 243, 107, 0.15)" }}>
            <strong style={{ color: "var(--signal-lime)", display: "block", marginBottom: 6 }}>2. Isolated Container Sandbox</strong>
            <p className="fine-print">Execution takes place inside dedicated non-root Docker containers with no network access, memory caps, and dropped capabilities.</p>
          </div>
          <div style={{ background: "rgba(41, 33, 60, 0.3)", padding: 14, borderRadius: 6, border: "1px solid rgba(183, 243, 107, 0.15)" }}>
            <strong style={{ color: "var(--signal-lime)", display: "block", marginBottom: 6 }}>3. Protected Security Suites</strong>
            <p className="fine-print">Repository-provided unit tests are never trusted for security verdicts. The backend mounts immutable external test suites to evaluate fixes.</p>
          </div>
        </div>
      </section>
    </div>
  );
}
