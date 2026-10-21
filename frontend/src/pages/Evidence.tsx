import { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import {
  Download,
  FileJson,
  Search,
  RefreshCw,
  AlertTriangle,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  Key,
  Lock,
  FileCheck,
  Info,
  GitPullRequest,
} from "lucide-react";
import { api } from "../api/jobs";
import { request } from "../api/client";
import type { AttestationVerificationResult, Job, SignedAttestation } from "../api/types";
import StatusBadge from "../components/StatusBadge";

export default function Evidence() {
  const location = useLocation();
  const navigate = useNavigate();
  const queryJobId = new URLSearchParams(location.search).get("jobId") || "";

  const [evidenceType, setEvidenceType] = useState<"job" | "scan_patch">("job");
  const [jobId, setJobId] = useState(queryJobId);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [evidence, setEvidence] = useState<Record<string, unknown> | null>(null);
  const [signedAttestation, setSignedAttestation] = useState<SignedAttestation | null>(null);
  const [githubBinding, setGithubBinding] = useState<{
    repo_full_name: string;
    pr_number: number;
    head_sha: string;
    base_sha: string;
    patch_hash: string;
    commit_status: string;
    is_stale: number;
  } | null>(null);

  // Independent verification state
  const [verifyingAttestation, setVerifyingAttestation] = useState(false);
  const [verificationResult, setVerificationResult] = useState<AttestationVerificationResult | null>(null);

  // Raw sandbox test state
  const [showSandbox, setShowSandbox] = useState(false);
  const [sandboxInput, setSandboxInput] = useState("");
  const [sandboxResult, setSandboxResult] = useState<AttestationVerificationResult | null>(null);
  const [sandboxBusy, setSandboxBusy] = useState(false);

  const [jobs, setJobs] = useState<Job[]>([]);
  const [jobsLoading, setJobsLoading] = useState(true);

  async function loadJobs() {
    setJobsLoading(true);
    try {
      const list = await api.jobs(50, 0);
      setJobs(list);
      if (!jobId && list.length > 0) {
        const target = list.find(j => ["VERIFIED", "VERIFICATION_FAILED"].includes(String(j.status))) || list[0];
        setJobId(target.job_id);
      }
    } catch {
      // ignore
    } finally {
      setJobsLoading(false);
    }
  }

  async function loadEvidence(targetId?: string) {
    const idToFetch = (targetId || jobId).trim();
    if (!idToFetch || busy) return;
    setBusy(true);
    setError("");
    setEvidence(null);
    setSignedAttestation(null);
    setGithubBinding(null);
    setVerificationResult(null);

    try {
      if (evidenceType === "job") {
        const evData = await api.evidence(idToFetch);
        setEvidence(evData as unknown as Record<string, unknown>);

        // Attempt to fetch signed attestation bundle
        try {
          const attestationData = await api.attestation(idToFetch);
          if (attestationData && attestationData.signature) {
            setSignedAttestation(attestationData);
            // Auto-verify signature for immediate confidence
            try {
              const vRes = await api.verifyAttestation(attestationData);
              setVerificationResult(vRes);
            } catch {
              // Non-blocking
            }
          }
        } catch {
          // Attestation endpoint might return 404 if verification not completed
        }

        // Fetch GitHub PR binding if present
        try {
          const gh = await api.githubBinding(idToFetch);
          if (gh?.binding) {
            setGithubBinding(gh.binding);
          }
        } catch {
          // Non-blocking
        }
      } else {
        const spData = await request<Record<string, unknown>>(`/api/scan-patches/${encodeURIComponent(idToFetch)}`);
        setEvidence(spData);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to retrieve evidence payload.");
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    void loadJobs();
  }, []);

  useEffect(() => {
    if (queryJobId) {
      setJobId(queryJobId);
      void loadEvidence(queryJobId);
    } else if (jobId) {
      void loadEvidence(jobId);
    }
  }, [queryJobId]);

  function handleSelectJob(id: string) {
    setJobId(id);
    navigate(`/evidence?jobId=${encodeURIComponent(id)}`, { replace: true });
    void loadEvidence(id);
  }

  function downloadEvidence() {
    if (evidence == null) return;
    const blob = new Blob([JSON.stringify(evidence, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sentinel-x-${evidenceType}-evidence-${jobId.trim()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function downloadAttestation() {
    if (signedAttestation == null) return;
    const blob = new Blob([JSON.stringify(signedAttestation, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sentinel-attestation-${jobId.trim()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  async function handleVerifyLive() {
    if (!signedAttestation) return;
    setVerifyingAttestation(true);
    try {
      const res = await api.verifyAttestation(signedAttestation);
      setVerificationResult(res);
    } catch (e) {
      setVerificationResult({
        valid: false,
        errors: [e instanceof Error ? e.message : "Verification request failed"],
      });
    } finally {
      setVerifyingAttestation(false);
    }
  }

  async function handleSandboxVerify() {
    if (!sandboxInput.trim()) return;
    setSandboxBusy(true);
    setSandboxResult(null);
    try {
      const parsed = JSON.parse(sandboxInput);
      const res = await api.verifyAttestation(parsed);
      setSandboxResult(res);
    } catch (e) {
      setSandboxResult({
        valid: false,
        errors: [e instanceof Error ? e.message : "Invalid JSON input or verification error"],
      });
    } finally {
      setSandboxBusy(false);
    }
  }

  return (
    <div className="page">
      <div className="page-heading">
        <div>
          <div className="eyebrow">AUDIT & PROVENANCE // LAB ATTESTATION</div>
          <h1>Evidence &amp; Verification Attestation</h1>
          <p>
            Cryptographically sealed, canonical RFC 8785 verification reports with Ed25519 digital signatures.
            Provides reproducible, independently inspectable evidence proving exact patch hashes, source digests,
            human approvals, and reconciled test outcomes.
          </p>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "360px 1fr", gap: 20, alignItems: "start" }}>
        {/* Left Column: Quick Job Selection */}
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <section className="panel">
            <div className="panel-heading">
              <div>
                <div className="eyebrow">WORKFLOW TARGET</div>
                <h2>Select Case</h2>
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

            <form
              onSubmit={e => {
                e.preventDefault();
                void loadEvidence();
              }}
              style={{ marginBottom: 14 }}
            >
              <div style={{ marginBottom: 10 }}>
                <label htmlFor="evidence-type" style={{ display: "block", fontSize: 12, marginBottom: 4 }}>
                  Target Type
                </label>
                <select
                  id="evidence-type"
                  value={evidenceType}
                  onChange={e => {
                    setEvidenceType(e.target.value as "job" | "scan_patch");
                    setEvidence(null);
                    setSignedAttestation(null);
                  }}
                  style={{ width: "100%", padding: "6px 10px", fontSize: 13 }}
                >
                  <option value="job">Protected Remediation Job</option>
                  <option value="scan_patch">Advisory Scan Patch</option>
                </select>
              </div>

              <label htmlFor="job-id" style={{ display: "block", fontSize: 12, marginBottom: 4 }}>
                Target Identifier
              </label>
              <div style={{ display: "flex", gap: 6 }}>
                <input
                  id="job-id"
                  value={jobId}
                  onChange={e => setJobId(e.target.value)}
                  placeholder={evidenceType === "job" ? "e.g. job-..." : "e.g. sp-..."}
                  required
                  style={{ flex: 1, padding: "6px 10px", fontSize: 13 }}
                />
                <button
                  type="submit"
                  className="button button-lime"
                  style={{ padding: "6px 12px" }}
                  disabled={busy || !jobId.trim()}
                >
                  {busy ? <RefreshCw size={14} className="spin" /> : <Search size={14} />}
                </button>
              </div>
            </form>

            {evidenceType === "job" && (
              <div>
                <div style={{ fontSize: 11, color: "var(--lavender-muted)", marginBottom: 8 }}>
                  RECENT PERSISTED JOBS:
                </div>
                {jobsLoading ? (
                  <p className="fine-print">Loading cases…</p>
                ) : jobs.length === 0 ? (
                  <p className="fine-print">No jobs found in database.</p>
                ) : (
                  <div style={{ display: "flex", flexDirection: "column", gap: 6, maxHeight: 380, overflowY: "auto" }}>
                    {jobs.map(job => (
                      <div
                        key={job.job_id}
                        onClick={() => handleSelectJob(job.job_id)}
                        style={{
                          padding: "8px 10px",
                          borderRadius: 6,
                          cursor: "pointer",
                          border: "1px solid",
                          borderColor: jobId === job.job_id ? "var(--signal-lime)" : "rgba(183, 243, 107, 0.1)",
                          background: jobId === job.job_id ? "rgba(183, 243, 107, 0.08)" : "rgba(41, 33, 60, 0.3)",
                        }}
                      >
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                          <code style={{ fontSize: 11, color: "var(--signal-lime)" }}>{job.job_id}</code>
                          <StatusBadge status={job.status} />
                        </div>
                        <div style={{ fontSize: 12, color: "var(--warm-paper)", marginTop: 2 }}>
                          {job.finding?.type?.replaceAll("_", " ") || job.summary || "Security Finding"}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </section>

          {/* Independent Verification Sandbox Toggle */}
          <section className="panel" style={{ background: "rgba(23, 16, 37, 0.6)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <Key size={16} color="var(--signal-lime)" />
                <strong style={{ fontSize: "0.85rem" }}>Auditor Verification Sandbox</strong>
              </div>
              <button
                className="button button-ghost-sm"
                onClick={() => setShowSandbox(!showSandbox)}
                style={{ fontSize: "0.75rem", padding: "3px 8px" }}
              >
                {showSandbox ? "Hide" : "Open"}
              </button>
            </div>
            <p className="fine-print" style={{ margin: "6px 0 0" }}>
              Verify arbitrary or tampered attestation JSON payloads against the public Ed25519 cryptographic validator.
            </p>
            {showSandbox && (
              <div style={{ marginTop: 12 }}>
                <textarea
                  value={sandboxInput}
                  onChange={e => setSandboxInput(e.target.value)}
                  placeholder="Paste signed attestation JSON here..."
                  rows={6}
                  style={{
                    width: "100%",
                    fontSize: 11,
                    fontFamily: "monospace",
                    background: "rgba(0,0,0,0.4)",
                    color: "var(--cream-soft)",
                    borderRadius: 4,
                    padding: 8,
                    boxSizing: "border-box",
                  }}
                />
                <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
                  <button
                    className="button button-lime"
                    style={{ fontSize: "0.75rem", padding: "5px 12px" }}
                    onClick={handleSandboxVerify}
                    disabled={sandboxBusy || !sandboxInput.trim()}
                  >
                    {sandboxBusy ? "Verifying…" : "Validate Attestation"}
                  </button>
                  {signedAttestation && (
                    <button
                      className="button button-secondary"
                      style={{ fontSize: "0.75rem", padding: "5px 10px" }}
                      onClick={() => setSandboxInput(JSON.stringify(signedAttestation, null, 2))}
                    >
                      Paste Current
                    </button>
                  )}
                </div>

                {sandboxResult && (
                  <div
                    style={{
                      marginTop: 10,
                      padding: 10,
                      borderRadius: 6,
                      background: sandboxResult.valid ? "rgba(34, 197, 94, 0.1)" : "rgba(239, 68, 68, 0.15)",
                      border: `1px solid ${sandboxResult.valid ? "rgba(34, 197, 94, 0.3)" : "rgba(239, 68, 68, 0.4)"}`,
                    }}
                  >
                    <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: "0.8rem", fontWeight: 700 }}>
                      {sandboxResult.valid ? (
                        <>
                          <CheckCircle2 size={16} color="#4ade80" />
                          <span style={{ color: "#4ade80" }}>ATTESTATION VALID &amp; INTACT</span>
                        </>
                      ) : (
                        <>
                          <XCircle size={16} color="#f87171" />
                          <span style={{ color: "#f87171" }}>INTEGRITY VALIDATION REJECTED</span>
                        </>
                      )}
                    </div>
                    {sandboxResult.errors && sandboxResult.errors.length > 0 && (
                      <ul style={{ margin: "6px 0 0", paddingLeft: 18, fontSize: "0.75rem", color: "#fca5a5" }}>
                        {sandboxResult.errors.map((err, i) => (
                          <li key={i}>{err}</li>
                        ))}
                      </ul>
                    )}
                    {sandboxResult.valid && (
                      <div style={{ fontSize: "0.72rem", color: "var(--lavender-muted)", marginTop: 6, fontFamily: "monospace" }}>
                        Digest: {sandboxResult.canonical_digest?.slice(0, 24)}… | Key: {sandboxResult.key_id}
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </section>
        </div>

        {/* Right Column: Evidence Payload & Summary */}
        <div>
          {error && (
            <div className="error-banner" role="alert" style={{ marginBottom: 16 }}>
              <AlertTriangle size={15} /> {error}
            </div>
          )}

          {/* GitHub PR Integration Card */}
          {githubBinding && (
            <section
              className="panel"
              style={{
                marginBottom: 20,
                border: "1px solid rgba(88, 166, 255, 0.4)",
                background: "linear-gradient(180deg, rgba(23, 28, 48, 0.95), rgba(15, 18, 32, 0.95))",
                boxShadow: "0 4px 24px rgba(0,0,0,0.4)",
              }}
            >
              <div className="panel-heading" style={{ marginBottom: 16 }}>
                <div>
                  <div className="eyebrow" style={{ color: "#58a6ff" }}>
                    GITHUB PULL REQUEST INTEGRATION
                  </div>
                  <h2 style={{ fontSize: "1.15rem", display: "flex", alignItems: "center", gap: 8, margin: "4px 0 0" }}>
                    <GitPullRequest size={18} color="#58a6ff" />
                    {githubBinding.repo_full_name} #{githubBinding.pr_number}
                  </h2>
                </div>
                <div style={{ display: "flex", gap: 8 }}>
                  <span
                    className="badge"
                    style={{
                      background:
                        githubBinding.is_stale === 1
                          ? "rgba(148, 163, 184, 0.2)"
                          : githubBinding.commit_status === "success"
                          ? "rgba(74, 222, 128, 0.2)"
                          : githubBinding.commit_status === "failure"
                          ? "rgba(248, 113, 113, 0.2)"
                          : "rgba(250, 204, 21, 0.2)",
                      color:
                        githubBinding.is_stale === 1
                          ? "#94a3b8"
                          : githubBinding.commit_status === "success"
                          ? "#4ade80"
                          : githubBinding.commit_status === "failure"
                          ? "#f87171"
                          : "#facc15",
                      border: "1px solid currentColor",
                      fontSize: "0.75rem",
                    }}
                  >
                    {githubBinding.is_stale === 1
                      ? "SUPERSEDED (STALE)"
                      : `STATUS: ${githubBinding.commit_status.toUpperCase()}`}
                  </span>
                </div>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 12, fontSize: "0.8rem" }}>
                <div style={{ background: "rgba(0,0,0,0.3)", padding: "10px", borderRadius: 4 }}>
                  <span style={{ color: "var(--lavender-muted)", display: "block", fontSize: "0.72rem" }}>HEAD COMMIT SHA</span>
                  <code style={{ color: "var(--signal-lime)", fontFamily: "monospace" }}>{githubBinding.head_sha}</code>
                </div>
                <div style={{ background: "rgba(0,0,0,0.3)", padding: "10px", borderRadius: 4 }}>
                  <span style={{ color: "var(--lavender-muted)", display: "block", fontSize: "0.72rem" }}>BASE COMMIT SHA</span>
                  <code style={{ color: "var(--lavender-soft)", fontFamily: "monospace" }}>{githubBinding.base_sha}</code>
                </div>
                <div style={{ background: "rgba(0,0,0,0.3)", padding: "10px", borderRadius: 4 }}>
                  <span style={{ color: "var(--lavender-muted)", display: "block", fontSize: "0.72rem" }}>BOUND PATCH HASH</span>
                  <code style={{ color: "#a5b4fc", fontFamily: "monospace" }}>{githubBinding.patch_hash.slice(0, 24)}…</code>
                </div>
              </div>
            </section>
          )}

          {/* Attestation & Signature Card */}
          {signedAttestation && (
            <section
              className="panel"
              style={{
                marginBottom: 20,
                border: "1px solid rgba(183, 243, 107, 0.4)",
                background: "linear-gradient(180deg, rgba(32, 22, 52, 0.95), rgba(18, 12, 30, 0.95))",
                boxShadow: "0 4px 24px rgba(0,0,0,0.4)",
              }}
            >
              <div className="panel-heading" style={{ marginBottom: 16 }}>
                <div>
                  <div className="eyebrow" style={{ color: "var(--signal-lime)" }}>
                    ED25519 DIGITALLY SIGNED ATTESTATION
                  </div>
                  <h2>
                    <Lock size={18} color="var(--signal-lime)" />
                    Verification Attestation Contract (v1)
                  </h2>
                </div>
                <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  <button
                    className="button button-secondary"
                    onClick={handleVerifyLive}
                    disabled={verifyingAttestation}
                    style={{ fontSize: "0.8rem", padding: "6px 12px" }}
                  >
                    <FileCheck size={14} className={verifyingAttestation ? "spin" : ""} style={{ marginRight: 6 }} />
                    {verifyingAttestation ? "Validating…" : "Verify Cryptographic Seal"}
                  </button>
                  <button
                    className="button button-lime"
                    onClick={downloadAttestation}
                    style={{ fontSize: "0.8rem", padding: "6px 12px" }}
                  >
                    <Download size={14} style={{ marginRight: 6 }} />
                    Export Attestation JSON
                  </button>
                </div>
              </div>

              {/* Live Verification Result Banner */}
              {verificationResult && (
                <div
                  style={{
                    padding: "10px 14px",
                    borderRadius: 6,
                    marginBottom: 16,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    background: verificationResult.valid ? "rgba(34, 197, 94, 0.12)" : "rgba(239, 68, 68, 0.15)",
                    border: `1px solid ${verificationResult.valid ? "rgba(34, 197, 94, 0.3)" : "rgba(239, 68, 68, 0.4)"}`,
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    {verificationResult.valid ? (
                      <CheckCircle2 size={18} color="#4ade80" />
                    ) : (
                      <XCircle size={18} color="#f87171" />
                    )}
                    <div>
                      <strong style={{ fontSize: "0.85rem", color: verificationResult.valid ? "#4ade80" : "#f87171" }}>
                        {verificationResult.valid
                          ? "Digital Signature & All Consistency Checks Passed"
                          : "Attestation Validation Failed"}
                      </strong>
                      <span style={{ fontSize: "0.75rem", color: "var(--lavender-muted)", display: "block" }}>
                        {verificationResult.valid
                          ? `Algorithm: ${verificationResult.signature_algorithm} • Key ID: ${verificationResult.key_id} • Verified independently via RFC 8785 canonical digest.`
                          : verificationResult.errors.join("; ")}
                      </span>
                    </div>
                  </div>
                  <span
                    style={{
                      fontFamily: "monospace",
                      fontSize: "0.72rem",
                      padding: "2px 8px",
                      borderRadius: 4,
                      background: verificationResult.valid ? "rgba(34,197,94,0.2)" : "rgba(239,68,68,0.2)",
                      color: verificationResult.valid ? "#4ade80" : "#f87171",
                      fontWeight: 700,
                    }}
                  >
                    {verificationResult.valid ? "AUTHENTIC" : "INVALID"}
                  </span>
                </div>
              )}

              {/* Attestation Parameters Grid */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))", gap: 10, marginBottom: 16 }}>
                <div style={{ background: "rgba(0,0,0,0.35)", padding: 10, borderRadius: 6, border: "1px solid rgba(255,255,255,0.06)" }}>
                  <div style={{ fontSize: 11, color: "var(--lavender-muted)" }}>SIGNATURE ALGORITHM</div>
                  <strong style={{ fontSize: 13, color: "var(--signal-lime)", fontFamily: "monospace" }}>
                    {signedAttestation.signature_algorithm}
                  </strong>
                  <div style={{ fontSize: 11, color: "var(--lavender-muted)", marginTop: 2 }}>
                    Key ID: <code>{signedAttestation.key_id}</code>
                  </div>
                </div>

                <div style={{ background: "rgba(0,0,0,0.35)", padding: 10, borderRadius: 6, border: "1px solid rgba(255,255,255,0.06)" }}>
                  <div style={{ fontSize: 11, color: "var(--lavender-muted)" }}>CANONICAL DIGEST (RFC 8785)</div>
                  <code style={{ fontSize: 11, color: "#fff", display: "block", overflow: "hidden", textOverflow: "ellipsis" }}>
                    {signedAttestation.attestation.canonical_digest}
                  </code>
                  <div style={{ fontSize: 10, color: "var(--signal-lime)", marginTop: 2 }}>
                    SHA-256 over Canonical JSON
                  </div>
                </div>

                <div style={{ background: "rgba(0,0,0,0.35)", padding: 10, borderRadius: 6, border: "1px solid rgba(255,255,255,0.06)" }}>
                  <div style={{ fontSize: 11, color: "var(--lavender-muted)" }}>TESTS RECONCILIATION</div>
                  <strong style={{ fontSize: 13, color: "#fff" }}>
                    {signedAttestation.attestation.tests_summary.passed} passed / {signedAttestation.attestation.tests_summary.total} total
                  </strong>
                  <div style={{ fontSize: 11, color: "var(--signal-lime)", marginTop: 2 }}>
                    {signedAttestation.attestation.test_results?.length ?? 0} individual test records matched
                  </div>
                </div>

                <div style={{ background: "rgba(0,0,0,0.35)", padding: 10, borderRadius: 6, border: "1px solid rgba(255,255,255,0.06)" }}>
                  <div style={{ fontSize: 11, color: "var(--lavender-muted)" }}>APPROVAL BINDING</div>
                  <strong style={{ fontSize: 13, color: "#fff" }}>
                    {signedAttestation.attestation.approved_by}
                  </strong>
                  <div style={{ fontSize: 10, color: "var(--lavender-muted)", marginTop: 2 }}>
                    At: {new Date(signedAttestation.attestation.approved_at).toLocaleTimeString()}
                  </div>
                </div>
              </div>

              {/* Digital Signature String Display */}
              <div style={{ background: "rgba(0,0,0,0.4)", padding: "8px 12px", borderRadius: 6, marginBottom: 14, border: "1px solid rgba(255,255,255,0.05)" }}>
                <div style={{ fontSize: 11, color: "var(--lavender-muted)", marginBottom: 4, display: "flex", justifyContent: "space-between" }}>
                  <span>DIGITAL SIGNATURE (ED25519)</span>
                  <span style={{ fontSize: 10 }}>PROTECTED KEY: OUTSIDE CONTAINERS</span>
                </div>
                <code style={{ fontSize: 11, color: "var(--lavender-muted)", wordBreak: "break-all", display: "block" }}>
                  {signedAttestation.signature}
                </code>
              </div>

              {/* Claims & Limitations: Transparency Section */}
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginTop: 14 }}>
                <div style={{ background: "rgba(34, 197, 94, 0.05)", padding: 12, borderRadius: 6, border: "1px solid rgba(34, 197, 94, 0.2)" }}>
                  <div style={{ fontSize: "0.78rem", fontWeight: 700, color: "#4ade80", display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
                    <ShieldCheck size={14} /> What This Attestation Proves
                  </div>
                  <ul style={{ margin: 0, paddingLeft: 16, fontSize: "0.73rem", color: "#dcfce7", lineHeight: 1.4 }}>
                    {signedAttestation.attestation.claims_and_limitations?.what_it_proves?.map((claim, idx) => (
                      <li key={idx} style={{ marginBottom: 4 }}>{claim}</li>
                    )) || (
                      <>
                        <li>Exact patch bytes match the approved SHA-256 hash.</li>
                        <li>Individual test records reconcile with summary counts.</li>
                        <li>Attestation was signed with private key sentinel-key-2026-v1.</li>
                      </>
                    )}
                  </ul>
                </div>

                <div style={{ background: "rgba(255, 122, 112, 0.05)", padding: 12, borderRadius: 6, border: "1px solid rgba(255, 122, 112, 0.2)" }}>
                  <div style={{ fontSize: "0.78rem", fontWeight: 700, color: "#f87171", display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
                    <Info size={14} /> What This Attestation Does NOT Prove
                  </div>
                  <ul style={{ margin: 0, paddingLeft: 16, fontSize: "0.73rem", color: "#fee2e2", lineHeight: 1.4 }}>
                    {signedAttestation.attestation.claims_and_limitations?.what_it_does_not_prove?.map((limit, idx) => (
                      <li key={idx} style={{ marginBottom: 4 }}>{limit}</li>
                    )) || (
                      <>
                        <li>Does NOT prove the entire application is bug-free or secure.</li>
                        <li>Does NOT prove timestamps without external RFC 3161 TSA.</li>
                        <li>Does NOT prove tests are trustworthy without source inspection.</li>
                      </>
                    )}
                  </ul>
                </div>
              </div>
            </section>
          )}

          {/* Full Evidence Record View */}
          {evidence != null ? (
            <section className="panel">
              <div className="panel-heading">
                <div>
                  <div className="eyebrow">PERSISTED RAW EVIDENCE RECORD</div>
                  <h2>
                    <FileJson size={18} />
                    Evidence for {String(jobId)}
                  </h2>
                </div>
                <div style={{ display: "flex", gap: 8 }}>
                  <button className="button button-lime" onClick={downloadEvidence}>
                    <Download size={14} /> Export Evidence JSON
                  </button>
                </div>
              </div>

              {/* Structured Summary Cards */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 12, marginBottom: 16 }}>
                <div style={{ background: "rgba(41, 33, 60, 0.4)", padding: 12, borderRadius: 6, border: "1px solid rgba(183,243,107,0.15)" }}>
                  <div style={{ fontSize: 11, color: "var(--lavender-muted)" }}>STATUS VERDICT</div>
                  <strong style={{ fontSize: 16, color: "var(--signal-lime)" }}>
                    {String(evidence.status || evidence.verification_status || "RECORDED")}
                  </strong>
                </div>
                <div style={{ background: "rgba(41, 33, 60, 0.4)", padding: 12, borderRadius: 6, border: "1px solid rgba(183,243,107,0.15)" }}>
                  <div style={{ fontSize: 11, color: "var(--lavender-muted)" }}>CANONICAL PATCH HASH</div>
                  <code style={{ fontSize: 11 }}>
                    {String(evidence.patch_hash || evidence.approved_patch_hash || "—").slice(0, 20)}…
                  </code>
                </div>
                <div style={{ background: "rgba(41, 33, 60, 0.4)", padding: 12, borderRadius: 6, border: "1px solid rgba(183,243,107,0.15)" }}>
                  <div style={{ fontSize: 11, color: "var(--lavender-muted)" }}>SOURCE REVISION</div>
                  <code style={{ fontSize: 11 }}>
                    {String(evidence.source_revision || "—").slice(0, 20)}…
                  </code>
                </div>
              </div>

              <div style={{ fontSize: 12, color: "var(--lavender-muted)", display: "flex", alignItems: "center", gap: 8, marginBottom: 12, background: "rgba(23,16,37,0.5)", padding: "8px 12px", borderRadius: 4 }}>
                <ShieldCheck size={16} color="var(--signal-lime)" />
                <span>
                  Authoritative evidence from backend store. Contains verification runs, test outputs, human approval decisions, and lifecycle audits.
                </span>
              </div>

              <pre className="json-view" style={{ maxHeight: 520, overflow: "auto" }}>
                {JSON.stringify(evidence, null, 2)}
              </pre>
            </section>
          ) : (
            <div className="empty-state">
              {busy ? (
                <div>
                  <RefreshCw size={24} className="spin" style={{ marginBottom: 10 }} />
                  <div>Retrieving persisted evidence payload from backend…</div>
                </div>
              ) : (
                "Select a case from the list or query an ID to inspect its evidence record."
              )}
            </div>
          )}
        </div>
      </div>

      <section className="panel evidence-checklist" style={{ marginTop: 20 }}>
        <div className="eyebrow">EVIDENCE ARCHITECTURE</div>
        <h2>Authoritative Verification Chain &amp; Attestation</h2>
        <div className="checklist-grid">
          <div>
            <span>01</span>
            <strong>Original Finding</strong>
            <small>Immutable finding record, category, line reference, and severity.</small>
          </div>
          <div>
            <span>02</span>
            <strong>Patch Provenance</strong>
            <small>Deterministic SHA-256 patch digest and diff content.</small>
          </div>
          <div>
            <span>03</span>
            <strong>Human Approval Binding</strong>
            <small>Authenticated operator approval locked to exact patch hash &amp; source revision.</small>
          </div>
          <div>
            <span>04</span>
            <strong>Reconciled Test Suite</strong>
            <small>Individual test records matched with summary counts in isolated container.</small>
          </div>
          <div>
            <span>05</span>
            <strong>Canonical RFC 8785 Payload</strong>
            <small>Deterministic serialization of verification evidence without volatile tokens.</small>
          </div>
          <div>
            <span>06</span>
            <strong>Ed25519 Cryptographic Seal</strong>
            <small>Asymmetric signature using protected host signing keys with rotation support.</small>
          </div>
        </div>
      </section>
    </div>
  );
}