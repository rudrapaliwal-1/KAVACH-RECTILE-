import { useState } from "react";
import { Check, X, ShieldCheck, AlertTriangle, LoaderCircle, Copy, CheckCheck, UserCheck } from "lucide-react";
import { api } from "../api/jobs";
import type { EvidenceApproval, Job, Patch } from "../api/types";
import StatusBadge from "./StatusBadge";

interface ApprovalPanelProps {
  job: Job | null;
  patch: Patch | null;
  approval?: EvidenceApproval | null;
  onUpdated: () => void;
}

export default function ApprovalPanel({ job, patch, approval, onUpdated }: ApprovalPanelProps) {
  const [busy, setBusy] = useState<"APPROVE" | "REJECT" | null>(null);
  const [message, setMessage] = useState("");
  const [copied, setCopied] = useState(false);

  const canDecide = Boolean(
    job?.job_id &&
    patch?.patch_hash &&
    job.status === "AWAITING_APPROVAL" &&
    patch.policy_status === "PASSED"
  );

  async function decide(decision: "APPROVE" | "REJECT") {
    if (!job?.job_id || !patch?.patch_hash || busy || !canDecide) return;
    setBusy(decision);
    setMessage("");
    try {
      await api.approval(job.job_id, patch.patch_hash, decision);
      setMessage(decision === "APPROVE" ? "Approval recorded by backend." : "Rejection recorded by backend.");
      onUpdated();
    } catch (e) {
      setMessage(e instanceof Error ? e.message : "Decision failed. No local approval was recorded.");
    } finally {
      setBusy(null);
    }
  }

  function copyHash() {
    if (!patch?.patch_hash) return;
    navigator.clipboard.writeText(patch.patch_hash).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  const isRevised = (patch?.attempt ?? 0) > 0;

  return (
    <section className="panel approval-panel">
      <div className="panel-heading">
        <div>
          <div className="eyebrow">HUMAN CONTROL & AUDIT</div>
          <h3>Patch approval</h3>
        </div>
        <ShieldCheck size={18} className="text-lime" />
      </div>

      <div className="approval-status">
        <span>Workflow status</span>
        <StatusBadge status={patch?.approval_status || job?.status} />
      </div>

      {/* Recorded Approval Identity */}
      {approval && (
        <div
          className="recorded-approval"
          style={{
            background: "rgba(34,197,94,0.1)",
            border: "1px solid rgba(34,197,94,0.25)",
            borderRadius: 6,
            padding: "10px 12px",
            marginBottom: 12,
            fontSize: "0.82rem",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 6, color: "#4ade80", fontWeight: 600, marginBottom: 4 }}>
            <UserCheck size={16} /> Recorded Approval
          </div>
          <div>Decision: <strong>{approval.decision}</strong></div>
          <div>Operator / Principal: <strong>{approval.approved_by}</strong></div>
          {approval.binding?.identity_kind && (
            <div>Identity Kind: <code>{approval.binding.identity_kind}</code></div>
          )}
          <div style={{ color: "var(--text-muted, #889)", marginTop: 4 }}>
            {new Date(approval.created_at).toLocaleString()}
          </div>
        </div>
      )}

      {/* Revision Freshness Notice */}
      {isRevised && job?.status === "AWAITING_APPROVAL" && (
        <div className="notice" style={{ marginBottom: 12 }}>
          <AlertTriangle size={15} />
          <span>
            <strong>Revision {patch?.attempt}:</strong> A new patch hash was generated. Fresh human approval is required before verification can be requested.
          </span>
        </div>
      )}

      <div className="hash-label" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span>CANONICAL PATCH SHA-256</span>
        {patch?.patch_hash && (
          <button
            type="button"
            className="icon-button"
            onClick={copyHash}
            title="Copy patch hash"
            style={{ padding: "2px 6px", fontSize: "0.75rem", display: "inline-flex", alignItems: "center", gap: 4 }}
          >
            {copied ? <CheckCheck size={13} className="text-lime" /> : <Copy size={13} />}
            {copied ? "Copied" : "Copy"}
          </button>
        )}
      </div>
      <code className="hash-value">{patch?.patch_hash || "Not provided by backend"}</code>

      {!canDecide && !approval && (
        <div className="notice">
          <AlertTriangle size={15} />
          <span>Decision controls are enabled only when a patch passes backend policy and awaits human approval.</span>
        </div>
      )}

      {message && <div className="inline-message">{message}</div>}

      <div className="approval-actions">
        <button
          className="button button-danger-ghost"
          disabled={!canDecide || !!busy}
          onClick={() => void decide("REJECT")}
        >
          {busy === "REJECT" ? <LoaderCircle size={15} className="spin" /> : <X size={15} />} Reject patch
        </button>
        <button
          className="button button-primary"
          disabled={!canDecide || !!busy}
          onClick={() => void decide("APPROVE")}
        >
          {busy === "APPROVE" ? <LoaderCircle size={15} className="spin" /> : <Check size={15} />} Approve patch
        </button>
      </div>

      <p className="fine-print">
        Approval binds strictly to this exact canonical patch hash and job attempt. Any patch modification invalidates prior approvals.
      </p>
    </section>
  );
}