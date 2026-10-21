import { useState } from "react";
import { Link } from "react-router-dom";
import { CheckCircle2, XCircle, Clock3, FlaskConical, AlertTriangle, ShieldCheck, Box, Lock } from "lucide-react";
import type { MutationReport, VerificationResult } from "../api/types";
import { api } from "../api/jobs";
import StatusBadge from "./StatusBadge";

export default function VerificationPanel({ result }: { result?: VerificationResult | null }) {
  const [localMutationReport, setLocalMutationReport] = useState<MutationReport | null>(null);
  const [mutationLoading, setMutationLoading] = useState(false);
  const [mutationError, setMutationError] = useState("");

  if (!result) {
    return (
      <div className="empty-state">
        <FlaskConical size={20} />
        <strong>No verification result returned yet</strong>
        <span>Results will appear after the backend isolated verification engine executes the protected test suite.</span>
      </div>
    );
  }

  const status = String(result.status);
  const isVerified = status === "VERIFIED" || status === "PASSED";

  return (
    <div className="verification-panel">
      <div className="verification-hero">
        <div className={`verification-symbol ${isVerified ? "green" : "red"}`}>
          {isVerified ? <CheckCircle2 size={24} /> : <XCircle size={24} />}
        </div>
        <div>
          <div className="eyebrow">INDEPENDENT VERIFIER VERDICT</div>
          <h3>{status.replaceAll("_", " ")}</h3>
          <StatusBadge status={status} />
        </div>
      </div>

      <div className="test-grid">
        <div><span>Total tests</span><strong>{result.tests_total ?? "—"}</strong></div>
        <div><span>Passed</span><strong className="success-text">{result.tests_passed ?? "—"}</strong></div>
        <div><span>Failed</span><strong className="danger-text">{result.tests_failed ?? "—"}</strong></div>
        <div><span>Duration</span><strong>{result.duration_ms != null ? `${(result.duration_ms / 1000).toFixed(2)}s` : "—"}</strong></div>
      </div>

      {result.test_suite_id && (
        <div className="suite-info" style={{ marginTop: 12, fontSize: "0.85rem", color: "var(--text-muted, #889)" }}>
          <Box size={14} style={{ display: "inline", verticalAlign: "middle", marginRight: 5 }} />
          Protected Suite Profile: <code>{result.test_suite_id}</code>
        </div>
      )}

      {/* Individual Real Test Outcomes */}
      {result.test_results && result.test_results.length > 0 && (
        <div className="test-outcomes-section" style={{ marginTop: 16 }}>
          <h4 style={{ fontSize: "0.9rem", marginBottom: 8, display: "flex", alignItems: "center", gap: 6 }}>
            <ShieldCheck size={15} /> Real Protected Test Outcomes ({result.test_results.length})
          </h4>
          <div className="test-outcomes-table" style={{ background: "rgba(0,0,0,0.2)", borderRadius: 6, padding: "8px 12px" }}>
            {result.test_results.map((test, index) => {
              const pass = test.outcome.toLowerCase() === "passed";
              return (
                <div
                  key={`${test.name}-${index}`}
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    padding: "6px 0",
                    borderBottom: index < (result.test_results?.length ?? 0) - 1 ? "1px solid rgba(255,255,255,0.06)" : "none",
                    fontFamily: "monospace",
                    fontSize: "0.82rem",
                  }}
                >
                  <span style={{ color: "var(--text-primary, #eee)" }}>{test.name}</span>
                  <span
                    style={{
                      padding: "2px 8px",
                      borderRadius: 4,
                      fontSize: "0.75rem",
                      fontWeight: 600,
                      background: pass ? "rgba(34,197,94,0.15)" : "rgba(239,68,68,0.15)",
                      color: pass ? "#4ade80" : "#f87171",
                    }}
                  >
                    {test.outcome.toUpperCase()}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {!!result.failed_tests?.length && (!result.test_results || result.test_results.length === 0) && (
        <div className="failed-test-list" style={{ marginTop: 14 }}>
          <h4><AlertTriangle size={14} /> Failed tests</h4>
          {result.failed_tests.map(t => <code key={t}>{t}</code>)}
        </div>
      )}

      {/* Red Team Adversarial Verification Report */}
      {result.adversarial_report && (
        <div
          className="adversarial-report-card"
          style={{
            marginTop: 18,
            padding: "16px",
            borderRadius: 8,
            background: "rgba(23, 16, 37, 0.75)",
            border: "1px solid rgba(183, 243, 107, 0.25)",
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <ShieldCheck size={18} color="var(--signal-lime, #b7f36b)" />
              <strong style={{ fontSize: "0.95rem", color: "var(--cream-soft, #f7f3ea)" }}>
                Red Team Adversarial Evaluation
              </strong>
            </div>
            <span
              style={{
                fontSize: "0.72rem",
                padding: "2px 8px",
                borderRadius: 4,
                background: result.adversarial_report.vulnerability_mitigated
                  ? "rgba(183, 243, 107, 0.15)"
                  : "rgba(255, 122, 112, 0.15)",
                color: result.adversarial_report.vulnerability_mitigated
                  ? "var(--signal-lime, #b7f36b)"
                  : "var(--threat-coral, #ff7a70)",
                border: `1px solid ${
                  result.adversarial_report.vulnerability_mitigated
                    ? "rgba(183, 243, 107, 0.3)"
                    : "rgba(255, 122, 112, 0.3)"
                }`,
                fontFamily: "var(--font-mono, monospace)",
              }}
            >
              {result.adversarial_report.vulnerability_mitigated ? "VULNERABILITY MITIGATED" : "MITIGATION FAILED"}
            </span>
          </div>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))",
              gap: 8,
              marginBottom: 14,
            }}
          >
            <div style={{ background: "rgba(0,0,0,0.3)", padding: "8px 10px", borderRadius: 6 }}>
              <div style={{ fontSize: "0.72rem", color: "var(--lavender-muted, #b9a7e8)" }}>Attack Vectors</div>
              <strong style={{ fontSize: "1rem" }}>
                {result.adversarial_report.attack_scenarios_passed}/{result.adversarial_report.attack_scenarios_attempted}
              </strong>
            </div>
            <div style={{ background: "rgba(0,0,0,0.3)", padding: "8px 10px", borderRadius: 6 }}>
              <div style={{ fontSize: "0.72rem", color: "var(--lavender-muted, #b9a7e8)" }}>Regression Tests</div>
              <strong style={{ fontSize: "1rem" }}>
                {result.adversarial_report.regression_scenarios_passed}/{result.adversarial_report.regression_scenarios_total}
              </strong>
            </div>
            <div style={{ background: "rgba(0,0,0,0.3)", padding: "8px 10px", borderRadius: 6 }}>
              <div style={{ fontSize: "0.72rem", color: "var(--lavender-muted, #b9a7e8)" }}>Baseline Exploited</div>
              <strong style={{ fontSize: "1rem", color: "var(--signal-lime, #b7f36b)" }}>
                {result.adversarial_report.vulnerability_reproduced_on_baseline ? "YES (PROVEN)" : "NO"}
              </strong>
            </div>
            <div style={{ background: "rgba(0,0,0,0.3)", padding: "8px 10px", borderRadius: 6 }}>
              <div style={{ fontSize: "0.72rem", color: "var(--lavender-muted, #b9a7e8)" }}>Suite Version</div>
              <strong style={{ fontSize: "0.82rem", fontFamily: "monospace" }}>
                {result.adversarial_report.protected_suite_version}
              </strong>
            </div>
          </div>

          {/* Scenario Details List */}
          {result.adversarial_report.scenarios && result.adversarial_report.scenarios.length > 0 && (
            <div style={{ marginBottom: 12 }}>
              <div style={{ fontSize: "0.8rem", fontWeight: 600, marginBottom: 6, color: "var(--lavender-muted, #b9a7e8)" }}>
                Evaluated Scenarios ({result.adversarial_report.scenarios.length}):
              </div>
              <div style={{ maxHeight: 220, overflowY: "auto", display: "flex", flexDirection: "column", gap: 6 }}>
                {result.adversarial_report.scenarios.map((sc, sidx) => {
                  const passed = sc.execution_status === "passed";
                  return (
                    <div
                      key={sidx}
                      style={{
                        padding: "6px 10px",
                        borderRadius: 5,
                        background: passed ? "rgba(183, 243, 107, 0.04)" : "rgba(255, 122, 112, 0.08)",
                        border: `1px solid ${passed ? "rgba(183, 243, 107, 0.15)" : "rgba(255, 122, 112, 0.25)"}`,
                        fontSize: "0.78rem",
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span style={{ fontFamily: "monospace", fontWeight: 600 }}>{sc.scenario_id}</span>
                        <span
                          style={{
                            fontSize: "0.7rem",
                            padding: "1px 6px",
                            borderRadius: 3,
                            background: passed ? "rgba(183, 243, 107, 0.2)" : "rgba(255, 122, 112, 0.2)",
                            color: passed ? "var(--signal-lime, #b7f36b)" : "var(--threat-coral, #ff7a70)",
                            fontWeight: 600,
                          }}
                        >
                          {sc.execution_status.toUpperCase()}
                        </span>
                      </div>
                      <div style={{ color: "var(--cream-soft, #f7f3ea)", marginTop: 2 }}>{sc.security_property}</div>
                      <div style={{ fontSize: "0.72rem", color: "var(--lavender-muted, #b9a7e8)", marginTop: 2 }}>
                        Source: <code>{sc.test_source}</code> &bull; Expected: {sc.expected_behavior}
                      </div>
                      {sc.actual_result && (
                        <div style={{ fontSize: "0.72rem", fontFamily: "monospace", color: passed ? "#a7f3d0" : "#fca5a5", marginTop: 2 }}>
                          Result: {sc.actual_result}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Explicit Limitations and Untested Behaviors */}
          {result.adversarial_report.limitations && result.adversarial_report.limitations.length > 0 && (
            <div
              style={{
                marginTop: 10,
                padding: "8px 10px",
                borderRadius: 6,
                background: "rgba(0,0,0,0.25)",
                fontSize: "0.75rem",
                color: "var(--lavender-muted, #b9a7e8)",
              }}
            >
              <strong style={{ color: "var(--cream-soft, #f7f3ea)", display: "block", marginBottom: 4 }}>
                Evaluation Limitations & Scope:
              </strong>
              <ul style={{ margin: 0, paddingLeft: 18 }}>
                {result.adversarial_report.limitations.map((lim, lidx) => (
                  <li key={lidx}>{lim}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Security Disclaimer */}
          <div
            style={{
              marginTop: 10,
              fontSize: "0.72rem",
              lineHeight: 1.4,
              color: "rgba(255,255,255,0.6)",
              borderTop: "1px solid rgba(255,255,255,0.08)",
              paddingTop: 8,
              fontStyle: "italic",
            }}
          >
            &bull; {result.adversarial_report.disclaimer}
          </div>
        </div>
      )}

      {/* Test Quality & Controlled Mutation Testing Section */}
      {(() => {
        const mutationReport = localMutationReport || result.mutation_report;
        if (mutationReport) {
          return (
            <div
              className="mutation-report-card"
              style={{
                marginTop: 18,
                padding: "16px 20px",
                borderRadius: 8,
                background: "linear-gradient(180deg, rgba(30, 20, 50, 0.95), rgba(18, 12, 30, 0.95))",
                border: "1px solid rgba(183, 243, 107, 0.4)",
                boxShadow: "0 4px 20px rgba(0, 0, 0, 0.3)",
              }}
            >
              {/* Header */}
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <FlaskConical size={18} color="var(--signal-lime, #b7f36b)" />
                  <h4 style={{ margin: 0, fontSize: "0.98rem", fontWeight: 700, letterSpacing: "0.03em" }}>
                    Test Quality &amp; Mutation Resilience
                  </h4>
                  <span style={{ fontSize: "0.75rem", color: "var(--lavender-muted, #b9a7e8)", fontFamily: "monospace" }}>
                    ({mutationReport.test_suite_version})
                  </span>
                </div>

                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <div
                    style={{
                      fontSize: "1.1rem",
                      fontWeight: 800,
                      fontFamily: "monospace",
                      color: mutationReport.mutation_score >= 80 ? "var(--signal-lime, #b7f36b)" : "#fbbf24",
                    }}
                  >
                    {mutationReport.mutation_score.toFixed(1)}% Score
                  </div>
                </div>
              </div>

              {/* Formula and Metric Pills */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))", gap: 8, marginBottom: 14 }}>
                <div style={{ background: "rgba(0,0,0,0.35)", padding: "8px 12px", borderRadius: 6, border: "1px solid rgba(255,255,255,0.06)" }}>
                  <div style={{ fontSize: "0.72rem", color: "var(--lavender-muted, #aaa)" }}>Valid Mutants</div>
                  <strong style={{ fontSize: "0.95rem", color: "#fff" }}>{mutationReport.valid_mutants}</strong>
                  <span style={{ fontSize: "0.68rem", color: "var(--lavender-muted, #888)", display: "block" }}>of {mutationReport.total_mutants} total</span>
                </div>

                <div style={{ background: "rgba(34, 197, 94, 0.08)", padding: "8px 12px", borderRadius: 6, border: "1px solid rgba(34, 197, 94, 0.25)" }}>
                  <div style={{ fontSize: "0.72rem", color: "#4ade80" }}>Killed Mutants</div>
                  <strong style={{ fontSize: "0.95rem", color: "#4ade80" }}>{mutationReport.killed_mutants}</strong>
                  <span style={{ fontSize: "0.68rem", color: "rgba(74, 222, 128, 0.7)", display: "block" }}>Defects detected</span>
                </div>

                <div style={{ background: mutationReport.surviving_mutants > 0 ? "rgba(239, 68, 68, 0.1)" : "rgba(0,0,0,0.35)", padding: "8px 12px", borderRadius: 6, border: "1px solid " + (mutationReport.surviving_mutants > 0 ? "rgba(239, 68, 68, 0.3)" : "rgba(255,255,255,0.06)") }}>
                  <div style={{ fontSize: "0.72rem", color: mutationReport.surviving_mutants > 0 ? "#f87171" : "#aaa" }}>Surviving Mutants</div>
                  <strong style={{ fontSize: "0.95rem", color: mutationReport.surviving_mutants > 0 ? "#f87171" : "#fff" }}>{mutationReport.surviving_mutants}</strong>
                  <span style={{ fontSize: "0.68rem", color: "var(--lavender-muted, #888)", display: "block" }}>Test weaknesses</span>
                </div>

                <div style={{ background: "rgba(0,0,0,0.35)", padding: "8px 12px", borderRadius: 6, border: "1px solid rgba(255,255,255,0.06)" }}>
                  <div style={{ fontSize: "0.72rem", color: "var(--lavender-muted, #aaa)" }}>Excluded (Invalid)</div>
                  <strong style={{ fontSize: "0.95rem", color: "#e2e8f0" }}>{mutationReport.invalid_mutants + mutationReport.inconclusive_mutants}</strong>
                  <span style={{ fontSize: "0.68rem", color: "var(--lavender-muted, #888)", display: "block" }}>Excluded from score</span>
                </div>

                <div style={{ background: "rgba(0,0,0,0.35)", padding: "8px 12px", borderRadius: 6, border: "1px solid rgba(255,255,255,0.06)" }}>
                  <div style={{ fontSize: "0.72rem", color: "var(--lavender-muted, #aaa)" }}>Duration &amp; Formula</div>
                  <strong style={{ fontSize: "0.82rem", color: "#e2e8f0" }}>{mutationReport.duration_ms}ms</strong>
                  <span style={{ fontSize: "0.65rem", color: "var(--signal-lime, #b7f36b)", display: "block", fontFamily: "monospace" }}>
                    {mutationReport.calculation_formula}
                  </span>
                </div>
              </div>

              {/* Missing Security Scenarios / Test Weaknesses */}
              {mutationReport.surviving_mutant_weaknesses && mutationReport.surviving_mutant_weaknesses.length > 0 && (
                <div style={{ marginBottom: 12, padding: "8px 12px", borderRadius: 6, background: "rgba(239, 68, 68, 0.1)", border: "1px solid rgba(239, 68, 68, 0.3)" }}>
                  <div style={{ fontSize: "0.78rem", fontWeight: 700, color: "#f87171", display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
                    <AlertTriangle size={13} /> Missing Security Scenarios / Test Weaknesses ({mutationReport.surviving_mutant_weaknesses.length})
                  </div>
                  <ul style={{ margin: 0, paddingLeft: 18, fontSize: "0.75rem", color: "#fecaca" }}>
                    {mutationReport.surviving_mutant_weaknesses.map((weakness, i) => (
                      <li key={i}>{weakness}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Mutant Variants Table */}
              <div style={{ marginTop: 10 }}>
                <div style={{ fontSize: "0.78rem", fontWeight: 700, color: "var(--lavender-muted, #ccc)", marginBottom: 6 }}>
                  Whitelisted Synthetic Mutation Operators ({mutationReport.mutants.length}):
                </div>
                <div style={{ maxHeight: 220, overflowY: "auto", borderRadius: 6, background: "rgba(0,0,0,0.25)", border: "1px solid rgba(255,255,255,0.05)" }}>
                  <table style={{ width: "100%", fontSize: "0.75rem", borderCollapse: "collapse" }}>
                    <thead>
                      <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.08)", color: "var(--lavender-muted, #aaa)", textAlign: "left" }}>
                        <th style={{ padding: "6px 10px" }}>ID</th>
                        <th style={{ padding: "6px 10px" }}>Operator</th>
                        <th style={{ padding: "6px 10px" }}>Description</th>
                        <th style={{ padding: "6px 10px" }}>Classification</th>
                        <th style={{ padding: "6px 10px" }}>Killing Test / Exclusion Reason</th>
                      </tr>
                    </thead>
                    <tbody>
                      {mutationReport.mutants.map(m => {
                        const isKilled = m.status === "KILLED";
                        const isSurvived = m.status === "SURVIVED";
                        const badgeBg = isKilled ? "rgba(34,197,94,0.15)" : isSurvived ? "rgba(239,68,68,0.15)" : "rgba(148,163,184,0.15)";
                        const badgeColor = isKilled ? "#4ade80" : isSurvived ? "#f87171" : "#94a3b8";

                        return (
                          <tr key={m.mutant_id} style={{ borderBottom: "1px solid rgba(255,255,255,0.03)" }}>
                            <td style={{ padding: "6px 10px", fontFamily: "monospace", color: "#e2e8f0" }}>{m.mutant_id}</td>
                            <td style={{ padding: "6px 10px", fontFamily: "monospace", color: "var(--signal-lime, #b7f36b)" }}>{m.operator}</td>
                            <td style={{ padding: "6px 10px", color: "var(--text-secondary, #ccc)" }}>{m.description}</td>
                            <td style={{ padding: "6px 10px" }}>
                              <span style={{ padding: "2px 6px", borderRadius: 4, fontWeight: 700, fontSize: "0.7rem", background: badgeBg, color: badgeColor }}>
                                {m.status}
                              </span>
                            </td>
                            <td style={{ padding: "6px 10px", color: isKilled ? "#4ade80" : isSurvived ? "#f87171" : "#94a3b8", fontFamily: "monospace", fontSize: "0.72rem" }}>
                              {m.killing_test || m.exclusion_reason || m.execution_output || "—"}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Test Quality Disclaimer */}
              <div
                style={{
                  marginTop: 12,
                  fontSize: "0.72rem",
                  lineHeight: 1.4,
                  color: "rgba(255,255,255,0.55)",
                  borderTop: "1px solid rgba(255,255,255,0.08)",
                  paddingTop: 8,
                  fontStyle: "italic",
                }}
              >
                &bull; Test Suite Quality Metric: This score measures the defect-detection rigor and resilience of protected test assertions against synthetic mutations. Do NOT present this as an overall application security score.
              </div>
            </div>
          );
        }

        if (result.job_id) {
          return (
            <div style={{ marginTop: 14, padding: "12px 16px", borderRadius: 6, background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.08)", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <div>
                <strong style={{ fontSize: "0.85rem", display: "block" }}>Test Quality &amp; Mutation Analysis</strong>
                <span style={{ fontSize: "0.75rem", color: "var(--lavender-muted, #888)" }}>Evaluate whether protected tests detect synthetic security defects.</span>
              </div>
              <button
                className="button button-secondary"
                style={{ fontSize: "0.78rem", padding: "6px 12px" }}
                disabled={mutationLoading}
                onClick={async () => {
                  try {
                    setMutationLoading(true);
                    setMutationError("");
                    const rep = await api.mutationTest(result.job_id);
                    setLocalMutationReport(rep);
                  } catch (err: unknown) {
                    setMutationError(err instanceof Error ? err.message : "Mutation test execution failed");
                  } finally {
                    setMutationLoading(false);
                  }
                }}
              >
                <FlaskConical size={14} className={mutationLoading ? "spin" : ""} style={{ marginRight: 6 }} />
                {mutationLoading ? "Running Mutants…" : "Measure Test Rigor"}
              </button>
            </div>
          );
        }

        return null;
      })()}
      {mutationError && (
        <div style={{ marginTop: 8, fontSize: "0.75rem", color: "var(--threat-coral, #ff7a70)" }}>
          {mutationError}
        </div>
      )}

      {result.execution_error && (
        <div className="execution-error" style={{ marginTop: 14 }}>
          <AlertTriangle size={15} />
          <div>
            <strong>Verifier execution error</strong>
            <pre style={{ margin: "4px 0 0", whiteSpace: "pre-wrap" }}>{result.execution_error}</pre>
            <p style={{ margin: "4px 0 0", fontSize: "0.8rem", color: "var(--text-muted, #aaa)" }}>
              Execution errors indicate runner/environment issues (e.g. Docker daemon not running or image missing), not test assertion failures.
            </p>
          </div>
        </div>
      )}

      <div className="hash-label" style={{ marginTop: 16 }}>VERIFIED PATCH HASH</div>
      <code className="hash-value">{result.patch_hash || "Not provided"}</code>

      {result.job_id && (
        <div
          style={{
            marginTop: 14,
            padding: "10px 14px",
            borderRadius: 6,
            background: "rgba(183, 243, 107, 0.05)",
            border: "1px solid rgba(183, 243, 107, 0.25)",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <Lock size={15} color="var(--signal-lime, #b7f36b)" />
            <div>
              <strong style={{ fontSize: "0.82rem", color: "var(--cream-soft, #f7f3ea)", display: "block" }}>
                Ed25519 Cryptographic Verification Attestation
              </strong>
              <span style={{ fontSize: "0.72rem", color: "var(--lavender-muted, #b9a7e8)" }}>
                Canonical RFC 8785 contract signed by isolated host verifier.
              </span>
            </div>
          </div>
          <Link
            to={`/evidence?jobId=${encodeURIComponent(result.job_id)}`}
            className="button button-lime"
            style={{ fontSize: "0.75rem", padding: "4px 10px", textDecoration: "none" }}
          >
            Inspect Attestation
          </Link>
        </div>
      )}

      <p className="fine-print">
        <Clock3 size={12} /> Passing the required tests is evidence for this isolated test suite and patch—not proof that the entire application is secure.
      </p>
    </div>
  );
}