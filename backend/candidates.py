"""AI-Agnostic Patch Intake and Comparison Lab for SENTINEL-X.

Enables developers to submit candidate patches from different AI coding tools
(e.g., Claude, Cursor, GitHub Copilot, DeepSeek) or manual development.

Guarantees:
1. Verifier and policy engine are independent of the authoring tool.
2. User-supplied model names, claimed hashes, and claimed verification results are never trusted.
3. Authoritative SHA-256 hashes and target source revisions are recomputed on the backend.
4. All candidates require explicit human approval and execute in isolated containers.
5. Multi-candidate comparison provides normalized technical facts without arbitrary composite scores.
6. Unsupported patch formats (CRLF, binary, non-unified diffs, prohibited edits) are strictly rejected.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional, Tuple
from uuid import uuid4

from .config import Settings
from .models import Status, WorkflowError
from .policy import patch_hash, validate_patch
from .schemas import (
    CandidateSummary,
    ComparisonReport,
    Finding,
    PatchIntakeRequest,
    PatchIntakeResponse,
)
from .auth import identity_kind, principal
from .manifest import TARGET_MANIFEST
from verification.patch_validator import PatchValidator, PatchValidationError


UNSUPPORTED_FORMAT_EXPLANATIONS = {
    "CRLF_LINE_ENDINGS": "Windows CRLF (\\r\\n) line endings detected. Candidate patches must use standard UNIX line endings (\\n).",
    "BINARY_PATCH": "Binary patch format is not supported. Candidate patches must be UTF-8 unified diffs.",
    "NON_UNIFIED_DIFF": "Patch does not start with standard Git unified diff header ('diff --git a/... b/...'). Context and normal diffs are unsupported.",
    "PROHIBITED_OPERATION": "Patch contains prohibited Git operations such as file creation, deletion, rename, mode change, or binary markers.",
    "PROTECTED_FILE_MODIFICATION": "Patch modifies files outside authorized target or attempts to alter protected tests, Dockerfiles, or runner scripts.",
    "NON_UTF8_ENCODING": "Patch contains non-UTF-8 characters or embedded null bytes.",
}


def _id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex}"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _raw_parse_and_validate_unified_diff(patch_text: str) -> Tuple[List[str], int, int]:
    if not patch_text or not patch_text.strip():
        raise WorkflowError("Candidate patch diff cannot be empty", 422, "EMPTY_PATCH")

    # Reject non-UTF-8 or null bytes
    if "\x00" in patch_text:
        raise WorkflowError(UNSUPPORTED_FORMAT_EXPLANATIONS["NON_UTF8_ENCODING"], 422, "UNSUPPORTED_PATCH_ENCODING")

    # Reject CRLF line endings
    if "\r" in patch_text:
        raise WorkflowError(UNSUPPORTED_FORMAT_EXPLANATIONS["CRLF_LINE_ENDINGS"], 422, "UNSUPPORTED_PATCH_ENCODING")

    # Reject binary markers
    for marker in PatchValidator.FORBIDDEN_MARKERS:
        if marker in patch_text:
            raise WorkflowError(
                f"{UNSUPPORTED_FORMAT_EXPLANATIONS['PROHIBITED_OPERATION']} Detected marker: '{marker.strip()}'.",
                422,
                "UNSUPPORTED_PATCH_FORMAT",
            )

    # Must start with diff --git
    lines = patch_text.split("\n")
    if not lines[0].startswith("diff --git "):
        raise WorkflowError(UNSUPPORTED_FORMAT_EXPLANATIONS["NON_UNIFIED_DIFF"], 422, "MALFORMED_DIFF")

    files_changed: List[str] = []
    additions = 0
    deletions = 0
    in_hunk = False

    for line in lines:
        if line.startswith("diff --git "):
            match = re.match(r"^diff --git a/(.+?) b/(.+?)$", line)
            if not match:
                raise WorkflowError("Malformed diff --git header in candidate patch", 422, "MALFORMED_DIFF")
            file_a, file_b = match.groups()
            if file_a != file_b:
                raise WorkflowError(
                    f"{UNSUPPORTED_FORMAT_EXPLANATIONS['PROHIBITED_OPERATION']} File renaming is not permitted.",
                    422,
                    "PROHIBITED_PATCH_OPERATION",
                )
            if file_a not in files_changed:
                files_changed.append(file_a)
            in_hunk = False
        elif line.startswith("@@ "):
            in_hunk = True
        elif in_hunk:
            if line.startswith("+") and not line.startswith("+++"):
                additions += 1
            elif line.startswith("-") and not line.startswith("---"):
                deletions += 1

    if not files_changed:
        raise WorkflowError("No target files identified in candidate patch diff", 422, "MALFORMED_DIFF")

    return files_changed, additions, deletions


def parse_and_validate_unified_diff(patch_text: str) -> Tuple[List[str], int, int]:
    """Validates diff syntax, checks for unsupported formats, and extracts changed files and line stats.
    
    Safe cached by patch text hash.
    """
    from .safe_cache import safe_cache
    return safe_cache.get_or_parse_diff(patch_text, _raw_parse_and_validate_unified_diff)



class CandidateLabEngine:
    """Manages AI-agnostic patch intake, policy enforcement, approval gating, and multi-candidate comparison."""

    def __init__(self, db: Any, settings: Settings, workflow: Any):
        self.db = db
        self.settings = settings
        self.workflow = workflow

    def _resolve_source_revision(self, project_id: Optional[str] = None) -> str:
        """Computes the authoritative source revision for the target."""
        try:
            root = self.workflow._source_root(project_id)
            return TARGET_MANIFEST.source_revision(root, self.settings.protected_tests_root)
        except Exception as err:
            raise WorkflowError("Target source revision is unavailable", 503, "SOURCE_UNAVAILABLE") from err

    def intake_candidate_patch(
        self,
        payload: PatchIntakeRequest,
        actor_id: str = "system",
    ) -> PatchIntakeResponse:
        """Validates and persists a candidate patch submission from any AI or manual source."""
        # 1. Diff Format Validation & Extraction (normalize trailing newline)
        patch_text = payload.patch_text or ""
        if patch_text and not patch_text.endswith("\n"):
            patch_text += "\n"
        files_changed, additions, deletions = parse_and_validate_unified_diff(patch_text)

        # 2. Authoritative Hash Recomputation (Never trust client hash)
        authoritative_hash = patch_hash(patch_text)

        # 3. Source Revision Validation (Never trust client revision)
        actual_source_revision = self._resolve_source_revision(payload.project_id)
        if payload.claimed_source_revision and payload.claimed_source_revision != actual_source_revision:
            raise WorkflowError(
                f"Target source revision has changed or does not match claimed revision. Expected {actual_source_revision[:16]}..., got {payload.claimed_source_revision[:16]}...",
                409,
                "STALE_SOURCE_REVISION",
            )

        # 4. Resolve Target App & Finding
        target_app = payload.target_app_id or "bola-demo-v1"
        finding_dict: dict[str, Any]
        if payload.job_id:
            with self.db.read() as db:
                existing_job = self.workflow._job(db, payload.job_id)
                finding_dict = json.loads(existing_job["finding_json"])
                target_app = existing_job["target_app_id"]
        elif payload.finding:
            finding_dict = payload.finding.model_dump()
        else:
            finding_dict = {
                "id": payload.finding_id or "BOLA-001",
                "type": "BROKEN_OBJECT_LEVEL_AUTHORIZATION",
                "severity": "HIGH",
                "file_path": files_changed[0] if files_changed else "app/access.py",
                "description": "Candidate patch submission for access control vulnerability",
            }

        finding_id = str(finding_dict.get("id", "BOLA-001"))

        # 5. Policy & Safety Evaluation
        policy_reasons: List[str] = []
        policy_passed = True

        # Run backend policy
        try:
            target_to_eval = "bola-demo-v1" if not payload.project_id else target_app
            b_policy = validate_patch(target_to_eval, patch_text, files_changed, attempt=1, settings=self.settings)
            if not b_policy.allowed:
                policy_passed = False
                policy_reasons.extend(b_policy.reasons)
        except Exception as e:
            policy_passed = False
            policy_reasons.append(str(e))

        # Run verification patch validator safety scan
        try:
            PatchValidator.validate_patch(patch_text, expected_hash=authoritative_hash)
        except PatchValidationError as pve:
            policy_passed = False
            policy_reasons.append(str(pve))

        # Deduplicate reasons
        clean_reasons = list(dict.fromkeys(policy_reasons))
        policy_status = "PASSED" if policy_passed else "REJECTED"
        initial_status = Status.AWAITING_APPROVAL.value if policy_passed else Status.POLICY_REJECTED.value

        # 6. Persistence in Authoritative SQLite Store
        job_id = _id("job")
        candidate_id = _id("cand")
        patch_id = _id("patch")
        now = _utc_now()
        source_label = payload.authoring_source.strip() or "External Developer / Tool"

        with self.db.transaction() as db:
            # Insert Jobs record
            db.execute("""
                INSERT INTO jobs (id, target_app_id, finding_json, status, attempt, created_at, updated_at)
                VALUES (?, ?, ?, ?, 1, ?, ?)
            """, (job_id, target_app, json.dumps(finding_dict), initial_status, now, now))

            # Bind Target Source Revision & Profile
            db.execute("""
                INSERT INTO job_bindings (job_id, source_revision, verification_profile)
                VALUES (?, ?, ?)
            """, (job_id, actual_source_revision, "bola-protected-tests-v1"))

            # Associate with project if project_id supplied
            if payload.project_id:
                db.execute("""
                    INSERT INTO project_jobs (job_id, project_id)
                    VALUES (?, ?)
                """, (job_id, payload.project_id))

            # Insert Patch Proposal Record
            db.execute("""
                INSERT INTO patch_proposals (
                    id, job_id, attempt, root_cause, explanation, patch_format,
                    patch_text, files_changed_json, patch_hash, policy_status,
                    policy_details_json, created_at, authoring_source
                ) VALUES (?, ?, 1, ?, ?, 'unified_diff', ?, ?, ?, ?, ?, ?, ?)
            """, (
                patch_id,
                job_id,
                payload.root_cause,
                payload.explanation,
                patch_text,
                json.dumps(files_changed),
                authoritative_hash,
                policy_status,
                json.dumps({"reasons": clean_reasons}),
                now,
                source_label,
            ))

            # Insert Candidate Patches Index Record
            db.execute("""
                INSERT INTO candidate_patches (
                    id, job_id, project_id, finding_id, authoring_source,
                    patch_format, patch_hash, source_revision, policy_status, created_at
                ) VALUES (?, ?, ?, ?, ?, 'unified_diff', ?, ?, ?, ?)
            """, (
                candidate_id,
                job_id,
                payload.project_id,
                finding_id,
                source_label,
                authoritative_hash,
                actual_source_revision,
                policy_status,
                now,
            ))

            # Record Workflow Audit Events
            db.execute("""
                INSERT INTO workflow_events (id, job_id, event_type, event_json, created_at)
                VALUES (?, ?, 'CANDIDATE_PATCH_SUBMITTED', ?, ?)
            """, (
                _id("evt"),
                job_id,
                json.dumps({
                    "candidate_id": candidate_id,
                    "authoring_source": source_label,
                    "patch_hash": authoritative_hash,
                    "source_revision": actual_source_revision,
                    "files_changed": files_changed,
                    "additions": additions,
                    "deletions": deletions,
                }),
                now,
            ))

            db.execute("""
                INSERT INTO workflow_events (id, job_id, event_type, event_json, created_at)
                VALUES (?, ?, 'POLICY_EVALUATED', ?, ?)
            """, (
                _id("evt"),
                job_id,
                json.dumps({
                    "patch_id": patch_id,
                    "patch_hash": authoritative_hash,
                    "outcome": policy_status,
                    "reasons": clean_reasons,
                }),
                now,
            ))

        return PatchIntakeResponse(
            job_id=job_id,
            candidate_id=candidate_id,
            patch_hash=authoritative_hash,
            authoring_source=source_label,
            source_revision=actual_source_revision,
            policy_status=policy_status,
            policy_reasons=clean_reasons,
            status=initial_status,
            created_at=now,
        )

    def list_candidates(
        self,
        project_id: Optional[str] = None,
        finding_id: Optional[str] = None,
    ) -> List[dict[str, Any]]:
        """Lists registered candidate patches with optional filters."""
        with self.db.read() as db:
            query = """
                SELECT c.*, j.status AS job_status, p.patch_text, p.root_cause, p.explanation,
                       p.files_changed_json
                FROM candidate_patches c
                JOIN jobs j ON j.id = c.job_id
                JOIN patch_proposals p ON p.job_id = c.job_id AND p.attempt = 1
                WHERE 1=1
            """
            params: List[Any] = []
            if project_id:
                query += " AND c.project_id = ?"
                params.append(project_id)
            if finding_id:
                query += " AND c.finding_id = ?"
                params.append(finding_id)
            query += " ORDER BY c.created_at DESC"

            rows = db.execute(query, params).fetchall()
            results = []
            for r in rows:
                item = dict(r)
                item["files_changed"] = json.loads(item.pop("files_changed_json", "[]"))
                results.append(item)
            return results

    def compare_candidates(self, job_ids: List[str]) -> ComparisonReport:
        """Performs a normalized, multi-factor comparison across candidate patches.
        
        Evaluates policy, diff size, mandatory test outcomes, regressions,
        adversarial attack scenarios, durations, and cryptographic evidence integrity.
        Does NOT compute an arbitrary composite score.
        """
        if not job_ids:
            raise WorkflowError("At least one candidate job ID is required for comparison", 400, "MISSING_JOB_IDS")

        summaries: List[CandidateSummary] = []
        observed_revisions: set[str] = set()
        observed_profiles: set[str] = set()
        notes: List[str] = []

        with self.db.read() as db:
            for jid in job_ids:
                job_row = db.execute("SELECT * FROM jobs WHERE id = ?", (jid,)).fetchone()
                if not job_row:
                    raise WorkflowError(f"Candidate job not found: {jid}", 404, "JOB_NOT_FOUND")
                job = dict(job_row)

                # Fetch proposal
                proposal_row = db.execute("""
                    SELECT * FROM patch_proposals WHERE job_id = ? AND attempt = 1
                """, (jid,)).fetchone()
                if not proposal_row:
                    raise WorkflowError(f"No patch proposal recorded for candidate job: {jid}", 404, "PROPOSAL_NOT_FOUND")
                proposal = dict(proposal_row)

                # Fetch binding
                binding_row = db.execute("SELECT * FROM job_bindings WHERE job_id = ?", (jid,)).fetchone()
                binding = dict(binding_row) if binding_row else {"source_revision": "unknown", "verification_profile": "unknown"}
                source_rev = binding["source_revision"]
                profile = binding["verification_profile"]
                observed_revisions.add(source_rev)
                observed_profiles.add(profile)

                # Fetch approval
                approval_row = db.execute("SELECT * FROM approvals WHERE job_id = ?", (jid,)).fetchone()
                approval = dict(approval_row) if approval_row else None

                # Fetch verification run
                run_row = db.execute("""
                    SELECT * FROM verification_runs WHERE job_id = ? ORDER BY created_at DESC LIMIT 1
                """, (jid,)).fetchone()
                run = dict(run_row) if run_row else None
                v_res = json.loads(run["result_json"]) if run and run.get("result_json") else None

                # Fetch attestation
                att_row = db.execute("SELECT * FROM run_attestations WHERE run_id = ?", (run["id"],)).fetchone() if run else None
                att = dict(att_row) if att_row else None

                # Compute diff stats
                diff_text = proposal.get("patch_text", "")
                try:
                    files_changed, adds, dels = parse_and_validate_unified_diff(diff_text)
                except Exception:
                    files_changed = json.loads(proposal.get("files_changed_json", "[]"))
                    adds = len([l for l in diff_text.splitlines() if l.startswith("+") and not l.startswith("+++")])
                    dels = len([l for l in diff_text.splitlines() if l.startswith("-") and not l.startswith("---")])

                # Adversarial report parsing
                adv_mitigated = None
                adv_summary = None
                limitations: List[str] = []
                if v_res and v_res.get("adversarial_report"):
                    adv = v_res["adversarial_report"]
                    adv_mitigated = adv.get("vulnerability_mitigated", False)
                    adv_summary = {
                        "attack_scenarios_passed": adv.get("attack_scenarios_passed", 0),
                        "attack_scenarios_attempted": adv.get("attack_scenarios_attempted", 0),
                        "regression_scenarios_passed": adv.get("regression_scenarios_passed", 0),
                        "regression_scenarios_total": adv.get("regression_scenarios_total", 0),
                        "baseline_exploited": adv.get("vulnerability_reproduced_on_baseline", True),
                    }
                    limitations = adv.get("limitations", [])

                # Evidence integrity check
                ev_integrity = None
                if att:
                    ev_integrity = {
                        "has_attestation": True,
                        "canonical_digest": att.get("evidence_digest", ""),
                        "signature_present": bool(att.get("signature")),
                        "key_id": att.get("key_id", "sentinel-key-2026-v1"),
                    }

                # Resolve Candidate ID
                cand_row = db.execute("SELECT id FROM candidate_patches WHERE job_id = ?", (jid,)).fetchone()
                candidate_id = cand_row["id"] if cand_row else jid

                policy_details = json.loads(proposal.get("policy_details_json", "{}"))

                summaries.append(CandidateSummary(
                    job_id=jid,
                    candidate_id=candidate_id,
                    authoring_source=proposal.get("authoring_source", "Ollama (Internal Agent)"),
                    status=job["status"],
                    policy_status=proposal["policy_status"],
                    policy_reasons=policy_details.get("reasons", []),
                    patch_hash=proposal["patch_hash"],
                    patch_size_bytes=len(diff_text.encode("utf-8")),
                    files_changed=files_changed,
                    additions=adds,
                    deletions=dels,
                    approval_status="APPROVED" if approval and approval["decision"] == "APPROVE" else "PENDING_APPROVAL" if not approval else "REJECTED",
                    approved_by=approval["approved_by"] if approval else None,
                    approved_at=approval["created_at"] if approval else None,
                    source_revision=source_rev,
                    test_suite_id=v_res.get("test_suite_id") if v_res else profile,
                    tests_total=v_res.get("tests_total") if v_res else None,
                    tests_passed=v_res.get("tests_passed") if v_res else None,
                    tests_failed=v_res.get("tests_failed") if v_res else None,
                    duration_ms=v_res.get("duration_ms") if v_res else None,
                    adversarial_mitigated=adv_mitigated,
                    adversarial_summary=adv_summary,
                    evidence_integrity=ev_integrity,
                    limitations=limitations,
                ))

        # Check for comparability discrepancies
        source_mismatch = len(observed_revisions) > 1
        suite_mismatch = len(observed_profiles) > 1

        if source_mismatch:
            notes.append(
                f"Source Revision Discrepancy: Candidates were evaluated against {len(observed_revisions)} different source revisions. Direct equivalence cannot be guaranteed without re-evaluating on the same revision."
            )
        else:
            notes.append("Execution Normalized: All candidates share the identical pinned source revision.")

        if suite_mismatch:
            notes.append(
                f"Test Profile Discrepancy: Candidates executed under {len(observed_profiles)} different test profiles."
            )
        else:
            notes.append("Test Profile Normalized: All candidates evaluated under the same protected test suite.")

        unapproved = [s.authoring_source for s in summaries if s.approval_status != "APPROVED"]
        if unapproved:
            notes.append(f"Approval Notice: {len(unapproved)} candidate(s) have not yet completed human approval ({', '.join(unapproved)}).")

        return ComparisonReport(
            candidates=summaries,
            normalized_source_revision=list(observed_revisions)[0] if not source_mismatch and observed_revisions else None,
            source_revision_mismatch=source_mismatch,
            test_suite_discrepancy=suite_mismatch,
            fair_comparison_notes=notes,
            disclaimer="SENTINEL-X reports factual security, policy, and regression outcomes for each candidate patch. It does not compute an arbitrary or unexplained composite score to declare a 'winner'."
        )
