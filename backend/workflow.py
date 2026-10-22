"""Durable workflow orchestration around untrusted planner output."""

import json
import hashlib
from datetime import datetime, timedelta, timezone
from dataclasses import replace
from pathlib import Path
from queue import Empty, Queue
from time import monotonic
import re
import sqlite3
from threading import Thread
from typing import Any
from uuid import uuid4

from agent.reflection import build_revision_guidance

from .approvals import approval_is_active, require_operator
from .auth import principal, identity_kind
from .config import Settings
from .database import Database, utc_now
from .middleware import correlation_id
from .lifecycle_telemetry import LifecycleTelemetry
from .models import Status, TRANSITIONS, WorkflowError
from .manifest import TARGET_MANIFEST
from .policy import AUTHORIZED_TARGET, patch_hash, validate_patch, validate_target
from .schemas import AgentProposal, ApprovalRequest, Finding, FindingRequest, VerificationResult
from pydantic import ValidationError
from .services.agent_adapter import AgentAdapter, bounded_source_context
from .services.verification_adapter import VerificationAdapter, VerificationRequest


def _id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex}"


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


def _bounded_call(function, timeout_seconds: float, heartbeat=None, heartbeat_interval=5.0):
    """Bound workflow wait time; a timed-out trusted call may still run briefly."""
    if timeout_seconds <= 0:
        raise ValueError("integration timeout must be positive")
    outcome: Queue[tuple[bool, Any]] = Queue(maxsize=1)

    def run():
        try:
            outcome.put((True, function()))
        except Exception as error:
            outcome.put((False, error))

    Thread(target=run, daemon=True).start()
    from time import monotonic
    deadline = monotonic() + timeout_seconds
    while True:
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise TimeoutError("integration timed out")
        try:
            success, value = outcome.get(timeout=min(remaining, heartbeat_interval))
            break
        except Empty:
            if heartbeat is not None:
                heartbeat()
    if not success:
        raise value
    return value


class Workflow:
    def __init__(self, db: Database, settings: Settings, agent: AgentAdapter,
                 verifier: VerificationAdapter):
        self.db = db
        self.settings = settings
        self.agent = agent
        self.verifier = verifier
        self.instance_id = _id("instance")
        self.telemetry = LifecycleTelemetry()

    def _telemetry(self, name: str, job_id: str | None = None,
                   project_id: str | None = None, run_id: str | None = None,
                   **fields: object) -> None:
        """Optional telemetry cannot affect remediation or the security verdict."""
        try:
            key = project_id or (self._project_id(job_id) if job_id else None) or job_id
            if key is None:
                return
            if self.telemetry.mode == "off":
                return
            with self.db.transaction() as db:
                correlation = self._opaque_telemetry_id(db, "scope:" + key)
                opaque_run = self._opaque_telemetry_id(db, "run:" + run_id) if run_id else None
            safe = {"correlation_id": correlation, **fields}
            if opaque_run is not None:
                safe["run_id"] = opaque_run
            self.telemetry.emit(name, **safe)
        except Exception:
            pass

    @staticmethod
    def _opaque_telemetry_id(db: sqlite3.Connection, resource_key: str) -> str:
        db.execute("INSERT OR IGNORE INTO telemetry_ids VALUES (?, ?)",
                   (resource_key, uuid4().hex))
        return db.execute("SELECT opaque_id FROM telemetry_ids WHERE resource_key = ?",
                          (resource_key,)).fetchone()["opaque_id"]

    def _project_id(self, job_id: str) -> str | None:
        with self.db.read() as db:
            row = db.execute("SELECT project_id FROM project_jobs WHERE job_id = ?", (job_id,)).fetchone()
        return row["project_id"] if row else None

    def _source_root(self, project_id: str | None = None) -> Path:
        return self.settings.project_root / project_id / "source" if project_id else self.settings.source_root

    def _source_revision(self, project_id: str | None = None) -> str:
        try:
            return TARGET_MANIFEST.source_revision(self._source_root(project_id),
                                                   self.settings.protected_tests_root)
        except (OSError, ValueError) as error:
            raise WorkflowError("authorized source is unavailable", 503, "SOURCE_UNAVAILABLE") from error

    def _binding(self, db: sqlite3.Connection, job_id: str) -> dict[str, Any]:
        row = _row(db.execute("SELECT * FROM job_bindings WHERE job_id = ?", (job_id,)).fetchone())
        if not row:
            raise WorkflowError("job target binding is missing", code="TARGET_BINDING_MISSING")
        return row

    def _require_current_source(self, db: sqlite3.Connection, job_id: str) -> dict[str, Any]:
        binding = self._binding(db, job_id)
        if binding["source_revision"] != self._source_revision(self._project_id(job_id)):
            raise WorkflowError("target source revision changed", code="STALE_SOURCE_REVISION")
        return binding

    def _job(self, db: sqlite3.Connection, job_id: str) -> dict[str, Any]:
        job = _row(db.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone())
        if not job:
            raise WorkflowError("job not found", 404, "JOB_NOT_FOUND")
        if identity_kind.get() == "DEMO_SHARED_TOKEN":
            if db.execute("SELECT 1 FROM project_jobs WHERE job_id = ?", (job_id,)).fetchone():
                raise WorkflowError("job not found", 404, "JOB_NOT_FOUND")
        if identity_kind.get() == "USER_SESSION":
            owner = db.execute("SELECT p.owner_id FROM project_jobs pj JOIN projects p ON p.id = pj.project_id WHERE pj.job_id = ?", (job_id,)).fetchone()
            if owner is not None and owner["owner_id"] != principal.get():
                raise WorkflowError("job not found", 404, "JOB_NOT_FOUND")
        return job

    def _current_patch(self, db: sqlite3.Connection, job: dict[str, Any]) -> dict[str, Any]:
        patch = _row(db.execute("""
            SELECT * FROM patch_proposals WHERE job_id = ? AND attempt = ?
        """, (job["id"], job["attempt"])).fetchone())
        if not patch:
            raise WorkflowError("current patch is not available", 404, "PATCH_NOT_FOUND")
        return patch

    def _event(self, db: sqlite3.Connection, job_id: str, event_type: str,
               payload: dict[str, Any]) -> None:
        now = utc_now()
        db.execute("INSERT INTO workflow_events VALUES (?, ?, ?, ?, ?)",
                   (_id("evt"), job_id, event_type,
                    _json({"correlation_id": correlation_id.get() or _id("op"),
                           "job_id": job_id, "event_type": event_type, "timestamp": now, **payload}), now))

    def _transition(self, db: sqlite3.Connection, job: dict[str, Any], next_status: Status,
                    details: dict[str, Any] | None = None) -> None:
        current = Status(job["status"])
        if next_status not in TRANSITIONS[current]:
            raise WorkflowError(f"invalid transition: {current} to {next_status}", code="INVALID_TRANSITION")
        now = utc_now()
        changed = db.execute("UPDATE jobs SET status = ?, updated_at = ?, version = version + 1 "
                             "WHERE id = ? AND status = ? AND version = ?",
                             (next_status.value, now, job["id"], current.value, job["version"]))
        if changed.rowcount != 1:
            raise WorkflowError("concurrent state change", code="STATE_CONFLICT")
        self._event(db, job["id"], "STATE_TRANSITION",
                    {"from": current.value, "to": next_status.value, **(details or {})})
        job["status"] = next_status.value
        job["version"] += 1

    def create_job(self, request: FindingRequest) -> dict[str, str]:
        project_id = request.target_app_id if request.target_app_id.startswith("project-") else None
        if project_id:
            if identity_kind.get() != "USER_SESSION":
                raise WorkflowError("user session required", 401, "AUTH_REQUIRED")
            with self.db.read() as db:
                project = db.execute("SELECT status FROM projects WHERE id = ? AND owner_id = ?",
                                     (project_id, principal.get())).fetchone()
            if project is None:
                raise WorkflowError("project not found", 404, "PROJECT_NOT_FOUND")
            if project["status"] != "SUPPORTED_BOLA_CONTRACT":
                raise WorkflowError("project does not match the supported BOLA contract", 422, "UNSUPPORTED_PROJECT")
        elif not validate_target(request.target_app_id) or identity_kind.get() == "USER_SESSION":
            raise WorkflowError("unauthorized target_app_id", 422, "UNAUTHORIZED_TARGET")
        if request.finding.file_path != "app/access.py" or request.finding.type != "BROKEN_OBJECT_LEVEL_AUTHORIZATION":
            raise WorkflowError("finding is outside supported BOLA contract", 422, "UNAUTHORIZED_FINDING_PATH")
        revision = self._source_revision(project_id)
        job_id = _id("job")
        now = utc_now()
        with self.db.transaction() as db:
            db.execute("""INSERT INTO jobs
                          (id, target_app_id, finding_json, status, attempt, created_at, updated_at)
                          VALUES (?, ?, ?, ?, ?, ?, ?)""",
                       (job_id, request.target_app_id, _json(request.finding.model_dump()),
                        Status.FINDING_RECEIVED.value, 0, now, now))
            db.execute("INSERT INTO job_bindings VALUES (?, ?, ?)",
                       (job_id, revision, TARGET_MANIFEST.verification_profile))
            if project_id:
                db.execute("INSERT INTO project_jobs VALUES (?, ?)", (job_id, project_id))
            self._event(db, job_id, "STATE_TRANSITION",
                        {"from": None, "to": Status.FINDING_RECEIVED.value})
        self._telemetry("finding.submitted", job_id, attempt=0, success=True)
        return {"job_id": job_id, "status": Status.FINDING_RECEIVED.value}

    def plan(self, job_id: str, feedback: dict[str, Any] | None = None) -> None:
        with self.db.transaction() as db:
            job = self._job(db, job_id)
            self._require_current_source(db, job_id)
            current = Status(job["status"])
            if current == Status.VERIFICATION_FAILED:
                if job["attempt"] >= self.settings.max_revisions:
                    self._transition(db, job, Status.RETRY_EXHAUSTED)
                    return
                job["attempt"] += 1
                db.execute("UPDATE jobs SET attempt = ? WHERE id = ?", (job["attempt"], job_id))
            elif current != Status.FINDING_RECEIVED:
                raise WorkflowError("planning is not allowed in current state")
            self._transition(db, job, Status.PLANNING, {"attempt": job["attempt"]})
            finding = Finding.model_validate(json.loads(job["finding_json"]))
            attempt = job["attempt"]
            target = job["target_app_id"]
            if attempt:
                # Only counts and trusted test identifiers enter Agent B; persist
                # the exact sanitized feedback before requesting a revision.
                self._event(db, job_id, "REFLECTION_STARTED",
                            {"attempt": attempt, "feedback": feedback})

        try:
            if attempt:
                build_revision_guidance(feedback, attempt)
                with self.db.transaction() as db:
                    self._event(db, job_id, "REFLECTION_COMPLETED",
                                {"attempt": attempt, "outcome": "GUIDANCE_VALIDATED"})
            source_start = monotonic()
            context = bounded_source_context(replace(self.settings, source_root=self._source_root(self._project_id(job_id))), finding)
            from .verification_metrics import verification_metrics
            verification_metrics.record_phase_timing("source_intake", min(3_600_000, int((monotonic() - source_start) * 1000)))

            # Advisory Regression Memory Retrieval
            from .regression_memory import retrieve_relevant_memory
            try:
                failed_tests = feedback.get("failed_tests") if feedback else None
                with self.db.read() as db:
                    advisory_memories = retrieve_relevant_memory(db, finding.type, finding.file_path, failed_tests, limit=3)
                if advisory_memories:
                    with self.db.transaction() as db:
                        self._event(db, job_id, "REGRESSION_MEMORY_ADVISORY", {
                            "count": len(advisory_memories),
                            "memories": advisory_memories,
                        })
            except Exception:
                pass

            inference_start = monotonic()
            self._telemetry("agent.inference.started", job_id, attempt=attempt)
            inference_success = False
            try:
                proposal = _bounded_call(
                    lambda: self.agent.propose_patch(finding.model_dump(), context, attempt, feedback),
                    self.settings.planner_timeout_seconds)
                proposal = AgentProposal.model_validate(proposal)
                inference_success = True
            finally:
                infer_dur = min(3_600_000, int((monotonic() - inference_start) * 1000))
                self._telemetry("agent.inference.completed", job_id, attempt=attempt,
                                success=inference_success,
                                duration_ms=infer_dur)
                verification_metrics.record_ai_generation(infer_dur, success=inference_success)
            self._telemetry("patch.generated", job_id, attempt=attempt, success=True)
            validation_start = monotonic()
            from .safe_cache import safe_cache
            digest = patch_hash(proposal.patch_text)
            target_to_eval = AUTHORIZED_TARGET if self._project_id(job_id) else target
            try:
                policy = safe_cache.get_or_compute_policy(
                    target_to_eval,
                    digest,
                    attempt,
                    lambda: validate_patch(target_to_eval, proposal.patch_text, proposal.files_changed, attempt, self.settings),
                )
            except Exception:
                val_dur = min(3_600_000, int((monotonic() - validation_start) * 1000))
                self._telemetry("patch.validation.completed", job_id, attempt=attempt,
                                success=False, duration_ms=val_dur)
                verification_metrics.record_phase_timing("policy_validation", val_dur)
                raise
            val_dur = min(3_600_000, int((monotonic() - validation_start) * 1000))
            self._telemetry("patch.validation.completed", job_id, attempt=attempt,
                            success=policy.allowed,
                            duration_ms=val_dur)
            verification_metrics.record_phase_timing("policy_validation", val_dur)
            with self.db.transaction() as db:
                job = self._job(db, job_id)
                if job["status"] != Status.PLANNING.value or job["attempt"] != attempt:
                    raise WorkflowError("planning result is stale")
                self._require_current_source(db, job_id)
                patch_id = _id("patch")
                digest = patch_hash(proposal.patch_text)
                db.execute("""
                    INSERT INTO patch_proposals (
                        id, job_id, attempt, root_cause, explanation, patch_format,
                        patch_text, files_changed_json, patch_hash, policy_status,
                        policy_details_json, created_at, authoring_source
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (patch_id, job_id, attempt, proposal.root_cause, proposal.explanation,
                        proposal.patch_format, proposal.patch_text, _json(proposal.files_changed),
                        digest, "PASSED" if policy.allowed else "REJECTED",
                        _json({"reasons": policy.reasons}), utc_now(), "Ollama (Internal Agent)"))
                self._event(db, job_id, "POLICY_EVALUATED",
                            {"patch_id": patch_id, "patch_hash": digest,
                             "outcome": "PASSED" if policy.allowed else "REJECTED",
                             "reasons": policy.reasons})
                self._transition(db, job, Status.AWAITING_APPROVAL if policy.allowed
                                 else Status.POLICY_REJECTED)
        except WorkflowError as error:
            self._planning_error(job_id, str(error))
        except ValidationError:
            self._planning_error(job_id, "malformed planner proposal")
        except TimeoutError:
            self._planning_error(job_id, "planner timed out")
        except Exception as exc:
            # GenerationError may wrap provider or parser failures. Persist only
            # a fixed category: exception messages can contain model output.
            category = getattr(exc, "failure_type", None)
            safe = {"ProviderTimeoutError", "ProviderError", "EditError", "ParseError"}
            if category not in safe:
                category = type(exc).__name__ if type(exc).__name__ in {"PlannerError", "RuntimeError"} else "GenerationError"
            self._planning_error(job_id, f"planner integration failed ({category})")

    def _planning_error(self, job_id: str, reason: str) -> None:
        with self.db.transaction() as db:
            job = self._job(db, job_id)
            if job["status"] == Status.PLANNING.value:
                self._transition(db, job, Status.EXECUTION_ERROR, {"reason": reason})

    def get_job(self, job_id: str) -> dict[str, Any]:
        with self.db.read() as db:
            job = self._job(db, job_id)
        job["finding"] = json.loads(job.pop("finding_json"))
        return job

    def list_jobs(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        with self.db.read() as db:
            if identity_kind.get() == "USER_SESSION":
                jobs = [dict(row) for row in db.execute(
                    """SELECT j.* FROM jobs j
                       LEFT JOIN project_jobs pj ON pj.job_id = j.id
                       LEFT JOIN projects p ON p.id = pj.project_id
                       WHERE pj.project_id IS NULL OR p.owner_id = ?
                       ORDER BY j.created_at DESC, j.id DESC LIMIT ? OFFSET ?""",
                    (principal.get(), limit, offset))]
            else:
                jobs = [dict(row) for row in db.execute(
                    "SELECT j.* FROM jobs j LEFT JOIN project_jobs pj ON pj.job_id = j.id WHERE pj.job_id IS NULL ORDER BY j.created_at DESC, j.id DESC LIMIT ? OFFSET ?",
                    (limit, offset))]
        for job in jobs:
            job["finding"] = json.loads(job.pop("finding_json"))
        return jobs

    def get_patch(self, job_id: str) -> dict[str, Any]:
        with self.db.read() as db:
            job = self._job(db, job_id)
            patch = self._current_patch(db, job)
        patch["files_changed"] = json.loads(patch.pop("files_changed_json"))
        patch["policy_details"] = json.loads(patch.pop("policy_details_json"))
        return patch

    def source(self, job_id: str) -> dict[str, Any]:
        with self.db.read() as db:
            job = self._job(db, job_id)
        finding = Finding.model_validate(json.loads(job["finding_json"]))
        project_id = self._project_id(job_id)
        source_root = self._source_root(project_id)
        context = bounded_source_context(replace(self.settings, source_root=source_root), finding)
        content = context.get(finding.file_path, "")
        return {
            "job_id": job_id,
            "file_path": finding.file_path,
            "content": content,
            "source_revision": self._source_revision(project_id),
        }

    def _invalidate_if_stale(self, job_id: str) -> None:
        with self.db.read() as reader:
            job = self._job(reader, job_id)
            binding = self._binding(reader, job_id)
        try:
            current = self._source_revision(self._project_id(job_id))
        except WorkflowError:
            current = None
        if current == binding["source_revision"]:
            return
        with self.db.transaction() as db:
            job = self._job(db, job_id)
            if job["status"] in (Status.AWAITING_APPROVAL.value, Status.VERIFYING.value):
                db.execute("""UPDATE verification_runs
                              SET status = ?, result_json = ?, completed_at = ?
                              WHERE job_id = ? AND status = 'RUNNING'""",
                           (Status.EXECUTION_ERROR.value,
                            _json({"execution_error": "target source revision changed"}),
                            utc_now(), job_id))
                self._transition(db, job, Status.EXECUTION_ERROR,
                                 {"reason": "target source revision changed"})
        raise WorkflowError("target source revision changed", code="STALE_SOURCE_REVISION")

    def decide(self, job_id: str, request: ApprovalRequest,
               supplied_token: str | None) -> dict[str, Any]:
        if identity_kind.get() == "USER_SESSION":
            operator = principal.get()
            approval_kind = "USER_SESSION"
        else:
            operator = require_operator(self.settings, supplied_token)
            approval_kind = "DEMO_SHARED_TOKEN"
        self._invalidate_if_stale(job_id)
        with self.db.transaction() as db:
            job = self._job(db, job_id)
            if job["status"] != Status.AWAITING_APPROVAL.value:
                raise WorkflowError("job is not awaiting approval")
            binding = self._require_current_source(db, job_id)
            patch = self._current_patch(db, job)
            if patch["policy_status"] != "PASSED":
                raise WorkflowError("patch policy did not pass")
            if patch["patch_hash"] != patch_hash(patch["patch_text"]):
                raise WorkflowError("stored patch hash mismatch", code="PATCH_INTEGRITY_ERROR")
            if request.patch_hash != patch["patch_hash"]:
                raise WorkflowError("stale or incorrect patch hash", code="PATCH_HASH_MISMATCH")
            approval_id = _id("approval")
            now = utc_now()
            db.execute("""INSERT INTO approvals
                          (id, job_id, patch_id, patch_hash, attempt, decision, approved_by, created_at)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                       (approval_id, job_id, patch["id"], request.patch_hash,
                        job["attempt"], request.decision, operator, now))
            db.execute("INSERT INTO approval_bindings VALUES (?, ?, ?, ?)",
                       (approval_id, job["target_app_id"], binding["source_revision"], approval_kind))
            self._event(db, job_id, "APPROVAL_DECIDED",
                        {"approval_id": approval_id, "patch_id": patch["id"],
                         "attempt": job["attempt"], "patch_hash": request.patch_hash,
                         "decision": request.decision,
                         "approved_by": operator, "identity_kind": approval_kind,
                         "source_revision": binding["source_revision"]})
            self._transition(db, job, Status.VERIFYING if request.decision == "APPROVE"
                             else Status.USER_REJECTED)
        self._telemetry("approval.recorded", job_id, attempt=job["attempt"],
                        success=request.decision == "APPROVE")
        return {"approval_id": approval_id, "job_id": job_id, "patch_id": patch["id"],
                "attempt": job["attempt"], "patch_hash": request.patch_hash,
                "decision": request.decision,
                "approved_by": operator, "identity_kind": approval_kind,
                "source_revision": binding["source_revision"], "created_at": now}

    def _renew_lease(self, run_id: str, lease_token: str) -> None:
        expiry = (datetime.now(timezone.utc) + timedelta(seconds=self.settings.lease_seconds)).isoformat()
        with self.db.transaction() as db:
            changed = db.execute("""
                UPDATE verification_leases SET expires_at = ?
                WHERE run_id = ? AND owner = ? AND token = ? AND expires_at > ?
            """, (expiry, run_id, self.instance_id, lease_token, utc_now()))
            if changed.rowcount != 1:
                raise WorkflowError("verification lease lost", code="LEASE_LOST")

    def verify(self, job_id: str) -> dict[str, Any]:
        self._invalidate_if_stale(job_id)
        with self.db.transaction() as db:
            job = self._job(db, job_id)
            if job["status"] != Status.VERIFYING.value:
                raise WorkflowError("job is not ready for verification")
            binding = self._require_current_source(db, job_id)
            patch = self._current_patch(db, job)
            if patch["patch_hash"] != patch_hash(patch["patch_text"]):
                raise WorkflowError("stored patch hash mismatch", code="PATCH_INTEGRITY_ERROR")
            if patch["policy_status"] != "PASSED":
                raise WorkflowError("patch policy did not pass")
            approval = _row(db.execute("SELECT * FROM approvals WHERE patch_id = ? AND decision = 'APPROVE'",
                                       (patch["id"],)).fetchone())
            if not approval or not approval_is_active(db, job_id, patch["id"],
                                                       patch["patch_hash"], approval["id"]):
                raise WorkflowError("active approval is required", code="APPROVAL_REQUIRED")
            if db.execute("SELECT id FROM verification_runs WHERE patch_id = ?",
                          (patch["id"],)).fetchone():
                raise WorkflowError("verification already started for this patch", code="VERIFICATION_ALREADY_STARTED")
            run_id = _id("run")
            lease_token = _id("lease")
            now = utc_now()
            expiry = (datetime.now(timezone.utc) + timedelta(seconds=self.settings.lease_seconds)).isoformat()
            db.execute("INSERT INTO verification_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                       (run_id, job_id, patch["id"], patch["patch_hash"], "RUNNING", "{}", now, None))
            db.execute("INSERT INTO verification_leases VALUES (?, ?, ?, ?)",
                       (run_id, self.instance_id, lease_token, expiry))
            self._event(db, job_id, "VERIFICATION_STARTED",
                        {"run_id": run_id, "patch_id": patch["id"], "patch_hash": patch["patch_hash"],
                         "attempt": job["attempt"], "source_revision": binding["source_revision"]})
            verify_request = VerificationRequest(job_id, job["target_app_id"], patch["id"],
                                                 patch["patch_text"], patch["patch_hash"], approval["id"],
                                                 job["attempt"], binding["source_revision"],
                                                 binding["verification_profile"], run_id,
                                                 self._project_id(job_id), str(self._source_root(self._project_id(job_id))))

        self._telemetry("verification.started", job_id, run_id=run_id, attempt=job["attempt"])
        from .verification_metrics import verification_metrics
        verification_start = monotonic()
        prep_start = monotonic()
        prep_dur = min(3_600_000, int((monotonic() - prep_start) * 1000))
        verification_metrics.record_phase_timing("docker_prep", prep_dur)

        def approval_verifier(check_job: str, check_patch: str,
                              check_hash: str, check_approval: str) -> bool:
            with self.db.read() as reader:
                return approval_is_active(reader, check_job, check_patch,
                                          check_hash, check_approval)

        try:
            result = _bounded_call(
                lambda: self.verifier.verify_patch(verify_request, approval_verifier),
                self.settings.verifier_timeout_seconds,
                heartbeat=lambda: self._renew_lease(run_id, lease_token),
                heartbeat_interval=min(5.0, self.settings.lease_seconds / 3))
            result = VerificationResult.model_validate(result)
            result.validate_counts()
            if result.status == "PASSED" and (result.test_suite_id != binding["verification_profile"]
                    or result.verification_profile != binding["verification_profile"]
                    or result.source_revision != binding["source_revision"]
                    or result.patch_hash != patch["patch_hash"] or result.run_id != run_id):
                raise ValueError("verification result does not match this run")
            result_data = result.model_dump()
            result_data["failed_tests"] = [re.sub(r"[^A-Za-z0-9_./:\-\[\]]", "_", name)[:128]
                                           for name in result_data["failed_tests"]]
            result_data["test_results"] = [
                {"name": re.sub(r"[^A-Za-z0-9_./:\-\[\]]", "_", item.get("name", ""))[:128],
                 "outcome": item.get("outcome", "")}
                for item in result_data.get("test_results", [])[:100]
                if item.get("outcome") in ("passed", "failed", "error", "skipped")]
            if result_data["execution_error"]:
                result_data["execution_error"] = "trusted verifier reported an execution error"
            status = (Status.VERIFIED if result.status == "PASSED" else
                      Status.VERIFICATION_FAILED if result.status == "FAILED" else
                      Status.EXECUTION_ERROR)
        except TimeoutError:
            result_data = {"execution_error": "verification timed out"}
            status = Status.EXECUTION_ERROR
        except ValueError:
            result_data = {"execution_error": "incomplete verification evidence"}
            status = Status.EXECUTION_ERROR
        except Exception:
            result_data = {"execution_error": "verification integration failed"}
            status = Status.EXECUTION_ERROR

        test_exec_dur = result_data.get("duration_ms", min(3_600_000, int((monotonic() - verification_start) * 1000)))
        verification_metrics.record_phase_timing("test_execution", test_exec_dur)

        with self.db.transaction() as db:
            job = self._job(db, job_id)
            lease = db.execute("""SELECT * FROM verification_leases
                                  WHERE run_id = ? AND owner = ? AND token = ? AND expires_at > ?""",
                               (run_id, self.instance_id, lease_token, utc_now())).fetchone()
            running = db.execute("SELECT status FROM verification_runs WHERE id = ?", (run_id,)).fetchone()
            if not lease or not running or running["status"] != "RUNNING" or job["status"] != Status.VERIFYING.value:
                raise WorkflowError("late verification result discarded", code="LEASE_LOST")
            if status == Status.VERIFIED:
                try:
                    current_revision = self._source_revision(self._project_id(job_id))
                except WorkflowError:
                    current_revision = None
                if current_revision != binding["source_revision"]:
                    result_data = {"execution_error": "target source revision changed"}
                    status = Status.EXECUTION_ERROR
            db.execute("""UPDATE verification_runs SET status = ?, result_json = ?, completed_at = ?
                          WHERE id = ? AND status = 'RUNNING'""",
                       (status.value, _json(result_data), utc_now(), run_id))
            if status in (Status.VERIFIED, Status.VERIFICATION_FAILED):
                from .attestation import AttestationEngine, compute_sha256
                legacy_digest = "sha256:" + hashlib.sha256(
                    _json({"run_id": run_id, "job_id": job_id, "patch_id": patch["id"],
                           "patch_hash": patch["patch_hash"], "attempt": job["attempt"],
                           "source_revision": binding["source_revision"],
                           "verification_profile": binding["verification_profile"],
                           "result": result_data}).encode("utf-8")).hexdigest()

                try:
                    src_root = self._source_root(self._project_id(job_id))
                    src_bytes = b"".join(sorted([f.read_bytes() for f in src_root.rglob("*") if f.is_file()]))
                    src_digest = compute_sha256(src_bytes)
                except Exception:
                    src_digest = compute_sha256(binding["source_revision"])

                tests_summary = {
                    "total": result_data.get("tests_total", 0),
                    "passed": result_data.get("tests_passed", 0),
                    "failed": result_data.get("tests_failed", 0),
                    "exit_status": 0 if status == Status.VERIFIED else 1,
                    "timed_out": False,
                    "infrastructure_status": "HEALTHY",
                }

                attestation_data = AttestationEngine.create_attestation(
                    run_id=run_id,
                    project_id=self._project_id(job_id),
                    job_id=job_id,
                    target_app_id=job["target_app_id"],
                    source_revision=binding["source_revision"],
                    source_digest=src_digest,
                    patch_hash=patch["patch_hash"],
                    attempt=job["attempt"],
                    patch_id=patch["id"],
                    approved_by=approval["approved_by"] if approval else self.settings.operator_name,
                    approved_at=approval["created_at"] if approval else utc_now(),
                    approval_id=approval["id"] if approval else "",
                    test_suite_id=binding["verification_profile"],
                    test_suite_version="bola-redteam-v1",
                    tests_summary=tests_summary,
                    test_results=result_data.get("test_results", []),
                    verdict=status.value,
                    container_image_digest=result_data.get("container_image_digest"),
                    execution_config={
                        "verifier_timeout_seconds": self.settings.verifier_timeout_seconds,
                        "python_version": "3.12.10",
                        "isolation_mode": "restricted_container" if getattr(self.verifier, "is_docker", False) else "process_sandbox",
                        "verifier_version": "sentinel-verifier-2.4.0",
                    },
                    sign=True,
                )

                sig_obj = attestation_data.get("digital_signature") or {}
                sig_str = sig_obj.get("signature_base64")
                key_id = sig_obj.get("key_id")
                sig_algo = sig_obj.get("algorithm")

                db.execute("""INSERT INTO run_attestations
                              (run_id, attempt, source_revision, verification_profile, test_suite_id,
                               evidence_digest, attestation_payload_json, signature, key_id, signature_algorithm)
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                           (run_id, job["attempt"], binding["source_revision"],
                            binding["verification_profile"], result_data.get("test_suite_id") or "",
                            legacy_digest, _json(attestation_data), sig_str, key_id, sig_algo))
            self._transition(db, job, status, {"run_id": run_id, "attempt": job["attempt"]})
            self._event(db, job_id, "VERIFICATION_COMPLETED",
                        {"run_id": run_id, "patch_hash": patch["patch_hash"], "status": status.value})
            can_retry = status == Status.VERIFICATION_FAILED
            exhausted = can_retry and job["attempt"] >= self.settings.max_revisions
            if exhausted:
                self._transition(db, job, Status.RETRY_EXHAUSTED)

        counts = {key: result_data[key] for key in ("tests_passed", "tests_failed")
                  if type(result_data.get(key)) is int}
        total_ver_dur = min(3_600_000, int((monotonic() - verification_start) * 1000))
        self._telemetry("verification.completed", job_id, run_id=run_id,
                        attempt=job["attempt"], success=status == Status.VERIFIED,
                        duration_ms=total_ver_dur,
                        **counts)
        verification_metrics.record_verification_run(
            attempt=job["attempt"],
            status=status.value,
            duration_ms=total_ver_dur,
            test_execution_ms=result_data.get("duration_ms", total_ver_dur),
            is_infra_error=(status == Status.EXECUTION_ERROR),
        )
        if status == Status.VERIFICATION_FAILED:
            from .regression_memory import record_failure_pattern
            try:
                with self.db.transaction() as db:
                    files_list = json.loads(patch["files_changed_json"]) if patch.get("files_changed_json") else ["app/access.py"]
                    record_failure_pattern(
                        db=db,
                        vulnerability_profile=binding["verification_profile"],
                        file_path=files_list[0] if files_list else "app/access.py",
                        failure_pattern=", ".join(result_data.get("failed_tests", [])[:3]) or "test failure",
                        sanitized_explanation=f"Tests failed on revision attempt {job['attempt']}: {result_data.get('tests_failed', 1)} failed",
                        remediation_pattern="Verify that object access strictly compares object owner with requester identity",
                        trusted_scenarios=result_data.get("failed_tests", [])[:5],
                        historical_limitations="Observed during test suite verification",
                    )
            except Exception:
                pass

        response = {"job_id": job_id, "patch_hash": patch["patch_hash"],
                    **result_data, "status": status.value}
        if can_retry and not exhausted:
            feedback = {"tests_total": result_data["tests_total"],
                        "tests_failed": result_data["tests_failed"],
                        "failed_tests": [re.sub(r"[^A-Za-z0-9_./:-]", "_", name)[:128]
                                         for name in result_data["failed_tests"][:20]]}
            self.plan(job_id, feedback)
        return response

    def run_mutation_testing(self, job_id: str) -> dict[str, Any]:
        """Execute controlled mutation testing suite for test quality measurement.

        Preserves authoritative patch verification results and job lifecycle status.
        Never overwrites or alters the verified status of an approved patch.
        """
        with self.db.read() as db:
            job = self._job(db, job_id)
            binding = self._require_current_source(db, job_id)

        from verification.mutator import MutationRunner
        report = MutationRunner.run_mutation_suite(
            source_revision=binding.get("source_revision", "")
        )
        report_dict = report.to_dict()

        with self.db.transaction() as db:
            self._event(db, job_id, "MUTATION_TESTING_COMPLETED", {
                "score": report.mutation_score,
                "valid_mutants": report.valid_mutants,
                "killed_mutants": report.killed_mutants,
                "surviving_mutants": report.surviving_mutants,
                "invalid_mutants": report.invalid_mutants,
                "test_suite_version": report.test_suite_version,
            })

        return report_dict

    def events(self, job_id: str) -> list[dict[str, Any]]:
        with self.db.read() as db:
            self._job(db, job_id)
            rows = db.execute("SELECT * FROM workflow_events WHERE job_id = ? ORDER BY rowid",
                              (job_id,)).fetchall()
        return [{**dict(row), "event": json.loads(row["event_json"])} for row in rows]

    def evidence(self, job_id: str) -> dict[str, Any]:
        with self.db.read() as db:
            job = self._job(db, job_id)
            patches = [dict(row) for row in db.execute(
                "SELECT * FROM patch_proposals WHERE job_id = ? ORDER BY attempt", (job_id,))]
            approvals = [dict(row) for row in db.execute(
                "SELECT * FROM approvals WHERE job_id = ? ORDER BY created_at", (job_id,))]
            runs = [dict(row) for row in db.execute(
                "SELECT * FROM verification_runs WHERE job_id = ? ORDER BY created_at", (job_id,))]
            binding = _row(db.execute("SELECT * FROM job_bindings WHERE job_id = ?", (job_id,)).fetchone())
            approval_bindings = {row["approval_id"]: dict(row) for row in db.execute(
                "SELECT ab.* FROM approval_bindings ab JOIN approvals a ON a.id = ab.approval_id "
                "WHERE a.job_id = ?", (job_id,))}
            attestations = {row["run_id"]: dict(row) for row in db.execute(
                "SELECT ra.* FROM run_attestations ra JOIN verification_runs vr ON vr.id = ra.run_id "
                "WHERE vr.job_id = ?", (job_id,))}
        job["finding"] = json.loads(job.pop("finding_json"))
        integrity_issues: list[str] = []
        for patch in patches:
            patch["files_changed"] = json.loads(patch.pop("files_changed_json"))
            patch["policy_details"] = json.loads(patch.pop("policy_details_json"))
            try:
                intact = patch_hash(patch["patch_text"]) == patch["patch_hash"]
            except UnicodeEncodeError:
                intact = False
            patch["hash_integrity"] = "VALID" if intact else "MISMATCH"
            if not intact:
                integrity_issues.append(f"patch hash mismatch: {patch['id']}")
        for approval in approvals:
            approval["binding"] = approval_bindings.get(approval["id"])
        for run in runs:
            run["result"] = json.loads(run.pop("result_json"))
            run["attestation"] = attestations.get(run["id"])
            if run["attestation"]:
                digest_input = {"run_id": run["id"], "job_id": job_id, "patch_id": run["patch_id"],
                                "patch_hash": run["patch_hash"],
                                "attempt": run["attestation"]["attempt"],
                                "source_revision": run["attestation"]["source_revision"],
                                "verification_profile": run["attestation"]["verification_profile"],
                                "result": run["result"]}
                computed = "sha256:" + hashlib.sha256(_json(digest_input).encode("utf-8")).hexdigest()
                payload_json = run["attestation"].get("attestation_payload_json")
                attestation_valid = True
                if payload_json:
                    from .attestation import AttestationEngine
                    try:
                        att_payload = json.loads(payload_json)
                        run["attestation"]["payload"] = att_payload
                        val_res = AttestationEngine.verify_attestation(att_payload, expected_run_id=run["id"])
                        run["attestation"]["validation"] = val_res.to_dict()
                        if not val_res.valid:
                            attestation_valid = False
                            integrity_issues.extend([f"attestation issue ({run['id']}): {issue}" for issue in val_res.issues])
                    except Exception as err:
                        attestation_valid = False
                        integrity_issues.append(f"attestation parse error ({run['id']}): {err}")

                legacy_match = computed == run["attestation"]["evidence_digest"]
                run["attestation_integrity"] = "VALID" if (legacy_match and attestation_valid) else "MISMATCH"
                if not legacy_match:
                    integrity_issues.append(f"attestation digest mismatch: {run['id']}")
        current = next((patch for patch in patches if patch["attempt"] == job["attempt"]), None)
        current_approval = next((approval for approval in approvals if current and
                                 approval["patch_id"] == current["id"] and
                                 approval["attempt"] == current["attempt"] and
                                 approval["patch_hash"] == current["patch_hash"] and
                                 approval["decision"] == "APPROVE" and binding and
                                 approval["binding"] and
                                 approval["binding"]["target_app_id"] == job["target_app_id"] and
                                 approval["binding"]["source_revision"] == binding["source_revision"] and
                                 approval["binding"]["identity_kind"] == ("USER_SESSION" if self._project_id(job_id) else "DEMO_SHARED_TOKEN")), None)
        current_run = next((run for run in runs if current and
                            run["patch_id"] == current["id"] and
                            run["patch_hash"] == current["patch_hash"] and
                            run["status"] == Status.VERIFIED.value), None)
        try:
            source_current = bool(binding and self._source_revision(self._project_id(job_id)) == binding["source_revision"])
        except WorkflowError:
            source_current = False
        verified = bool(job["status"] == Status.VERIFIED.value and source_current and binding and current and
                        current["hash_integrity"] == "VALID" and
                        current["policy_status"] == "PASSED" and current_approval and
                        current_run and current_run["result"].get("status") == "PASSED" and
                        current_run["result"].get("tests_total", 0) > 0 and
                        current_run["result"].get("tests_failed") == 0 and
                        current_run["result"].get("tests_collected") == current_run["result"].get("tests_total") and
                        current_run["result"].get("collection_complete") is True and
                        current_run["result"].get("execution_completed") is True and
                        current_run["result"].get("test_suite_id") == binding["verification_profile"] and
                        current_run["result"].get("run_id") == current_run["id"] and
                        current_run["result"].get("patch_hash") == current["patch_hash"] and
                        current_run["result"].get("source_revision") == binding["source_revision"] and
                        current_run["result"].get("verification_profile") == binding["verification_profile"] and
                        current_run["attestation"] and
                        current_run["attestation"]["attempt"] == job["attempt"] and
                        current_run["attestation"]["source_revision"] == binding["source_revision"] and
                        current_run["attestation"]["verification_profile"] == binding["verification_profile"] and
                        current_run["attestation"]["test_suite_id"] == binding["verification_profile"] and
                        current_run["attestation_integrity"] == "VALID")
        if job["status"] == Status.VERIFIED.value and not verified:
            integrity_issues.append("verified state lacks matching approved passing evidence")
        return {"job_id": job_id, "finding": job["finding"], "target_app_id": job["target_app_id"],
                "target_binding": binding, "source_revision_current": source_current,
                "status": job["status"], "patch_attempts": patches, "approvals": approvals,
                "verification_runs": runs,
                "failure_history": [run for run in runs if run["status"] in
                                    (Status.VERIFICATION_FAILED.value, Status.EXECUTION_ERROR.value)],
                "integrity_issues": integrity_issues,
                "conclusion": "VERIFIED" if verified else "NOT_VERIFIED",
                "limitations": ["Verification is limited to required tests actually reported by the trusted verifier.",
                                "Local accounts and sessions are intended for controlled deployments.",
                                "In-process execution has no distributed-worker durability."]}

    def attestation(self, job_id: str) -> dict[str, Any]:
        """Return the exportable signed verification attestation document for the job."""
        with self.db.read() as db:
            self._job(db, job_id)
            run = db.execute(
                "SELECT vr.*, ra.attestation_payload_json, ra.evidence_digest, ra.signature, ra.key_id, ra.signature_algorithm "
                "FROM verification_runs vr "
                "JOIN run_attestations ra ON ra.run_id = vr.id "
                "WHERE vr.job_id = ? AND vr.status IN ('VERIFIED', 'VERIFICATION_FAILED') "
                "ORDER BY vr.created_at DESC LIMIT 1",
                (job_id,)
            ).fetchone()
            if not run or not run["attestation_payload_json"]:
                raise WorkflowError("no verified attestation available for this job", code="ATTESTATION_NOT_FOUND", http_status=404)
        return json.loads(run["attestation_payload_json"])

    def recover_interrupted(self) -> None:
        """Expire only runs without a live lease; another process may still own one."""
        with self.db.transaction() as db:
            rows = db.execute("SELECT * FROM jobs WHERE status IN (?, ?)",
                              (Status.PLANNING.value, Status.VERIFYING.value)).fetchall()
            for row in rows:
                job = dict(row)
                if job["status"] == Status.PLANNING.value:
                    self._transition(db, job, Status.EXECUTION_ERROR,
                                     {"reason": "process interrupted"})
                    continue
                running = db.execute("""
                    SELECT vr.id, vl.expires_at FROM verification_runs vr
                    LEFT JOIN verification_leases vl ON vl.run_id = vr.id
                    WHERE vr.job_id = ? AND vr.status = 'RUNNING'
                """, (job["id"],)).fetchall()
                if not running:
                    continue  # Approved and waiting for explicit POST /verify.
                if any(run["expires_at"] and run["expires_at"] > utc_now() for run in running):
                    continue  # Another live process still owns the run.
                for run in running:
                    db.execute("""UPDATE verification_runs SET status = ?, result_json = ?, completed_at = ?
                                  WHERE id = ? AND status = 'RUNNING'""",
                               (Status.EXECUTION_ERROR.value,
                                _json({"execution_error": "process interrupted"}), utc_now(), run["id"]))
                self._transition(db, job, Status.EXECUTION_ERROR,
                                 {"reason": "verification lease expired"})
