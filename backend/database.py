"""SQLite storage with explicit write transactions."""

from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
import os
import sqlite3
from typing import Iterator


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # The database contains password hashes, sessions, source context and
        # approval evidence. Do not inherit a permissive host umask.
        descriptor = os.open(self.path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.close(descriptor)
        os.chmod(self.path, 0o600)
        self.initialize()
        self._secure_sidecars()

    def _secure_sidecars(self) -> None:
        for suffix in ("-wal", "-shm"):
            try:
                os.chmod(str(self.path) + suffix, 0o600)
            except (FileNotFoundError, PermissionError, OSError):
                pass

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        self._secure_sidecars()
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def initialize(self) -> None:
        with self.connect() as db:
            db.execute("PRAGMA journal_mode = WAL")
            db.executescript("""
                BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY,
                    target_app_id TEXT NOT NULL,
                    finding_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    attempt INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS patch_proposals (
                    id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL REFERENCES jobs(id),
                    attempt INTEGER NOT NULL,
                    root_cause TEXT NOT NULL,
                    explanation TEXT NOT NULL,
                    patch_format TEXT NOT NULL,
                    patch_text TEXT NOT NULL,
                    files_changed_json TEXT NOT NULL,
                    patch_hash TEXT NOT NULL,
                    policy_status TEXT NOT NULL,
                    policy_details_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(job_id, attempt)
                );
                CREATE TABLE IF NOT EXISTS approvals (
                    id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL REFERENCES jobs(id),
                    patch_id TEXT NOT NULL REFERENCES patch_proposals(id),
                    patch_hash TEXT NOT NULL,
                    attempt INTEGER NOT NULL,
                    decision TEXT NOT NULL,
                    approved_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(patch_id)
                );
                CREATE TABLE IF NOT EXISTS verification_runs (
                    id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL REFERENCES jobs(id),
                    patch_id TEXT NOT NULL REFERENCES patch_proposals(id),
                    patch_hash TEXT NOT NULL,
                    status TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    completed_at TEXT
                );
                CREATE TABLE IF NOT EXISTS workflow_events (
                    id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL REFERENCES jobs(id),
                    event_type TEXT NOT NULL,
                    event_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_events_job ON workflow_events(job_id, created_at);
                CREATE INDEX IF NOT EXISTS idx_runs_job ON verification_runs(job_id, created_at);
                CREATE UNIQUE INDEX IF NOT EXISTS idx_runs_patch ON verification_runs(patch_id);
                CREATE TRIGGER IF NOT EXISTS workflow_events_no_update
                    BEFORE UPDATE ON workflow_events BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS workflow_events_no_delete
                    BEFORE DELETE ON workflow_events BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
                CREATE TABLE IF NOT EXISTS job_bindings (
                    job_id TEXT PRIMARY KEY REFERENCES jobs(id),
                    source_revision TEXT NOT NULL,
                    verification_profile TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS approval_bindings (
                    approval_id TEXT PRIMARY KEY REFERENCES approvals(id),
                    target_app_id TEXT NOT NULL,
                    source_revision TEXT NOT NULL,
                    identity_kind TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS verification_leases (
                    run_id TEXT PRIMARY KEY REFERENCES verification_runs(id),
                    owner TEXT NOT NULL,
                    token TEXT NOT NULL UNIQUE,
                    expires_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS run_attestations (
                    run_id TEXT PRIMARY KEY REFERENCES verification_runs(id),
                    attempt INTEGER NOT NULL,
                    source_revision TEXT NOT NULL,
                    verification_profile TEXT NOT NULL,
                    test_suite_id TEXT NOT NULL,
                    evidence_digest TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    email TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    csrf_hash TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS projects (
                    id TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL,
                    status TEXT NOT NULL,
                    framework TEXT,
                    archive_name TEXT,
                    archive_sha256 TEXT,
                    source_revision TEXT,
                    created_at TEXT NOT NULL,
                    uploaded_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_projects_owner ON projects(owner_id, created_at);
                CREATE TABLE IF NOT EXISTS project_jobs (
                    job_id TEXT PRIMARY KEY REFERENCES jobs(id),
                    project_id TEXT NOT NULL REFERENCES projects(id)
                );
                CREATE TABLE IF NOT EXISTS telemetry_ids (
                    resource_key TEXT PRIMARY KEY,
                    opaque_id TEXT NOT NULL UNIQUE
                );
                CREATE TABLE IF NOT EXISTS project_scans (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    status TEXT NOT NULL,
                    framework TEXT NOT NULL,
                    languages_json TEXT NOT NULL,
                    manifest_json TEXT NOT NULL,
                    file_count INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    completed_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_scans_project ON project_scans(project_id, created_at);
                CREATE TABLE IF NOT EXISTS scan_findings (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL REFERENCES project_scans(id) ON DELETE CASCADE,
                    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    line_start INTEGER NOT NULL,
                    line_end INTEGER NOT NULL,
                    evidence TEXT NOT NULL,
                    explanation TEXT NOT NULL,
                    recommendation TEXT NOT NULL,
                    detection_source TEXT NOT NULL,
                    validation_status TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_findings_project ON scan_findings(project_id, scan_id);
                CREATE TABLE IF NOT EXISTS security_activity (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    actor_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    event_type TEXT NOT NULL,
                    reference_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_security_activity_project ON security_activity(project_id, created_at);
                CREATE TABLE IF NOT EXISTS scan_ai_reviews (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL REFERENCES project_scans(id) ON DELETE CASCADE,
                    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    consent_id TEXT NOT NULL REFERENCES source_share_consents(id) ON DELETE CASCADE,
                    model TEXT NOT NULL,
                    response_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_ai_reviews_scan ON scan_ai_reviews(scan_id, created_at);
                CREATE TABLE IF NOT EXISTS scan_patch_proposals (
                    id TEXT PRIMARY KEY,
                    finding_id TEXT NOT NULL REFERENCES scan_findings(id) ON DELETE CASCADE,
                    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    source_sha256 TEXT NOT NULL,
                    patch_hash TEXT NOT NULL,
                    diff TEXT NOT NULL,
                    replacement_line TEXT NOT NULL,
                    root_cause TEXT NOT NULL,
                    explanation TEXT NOT NULL,
                    model TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_scan_patches_finding ON scan_patch_proposals(finding_id, created_at);
                CREATE TABLE IF NOT EXISTS scan_patch_approvals (
                    id TEXT PRIMARY KEY,
                    proposal_id TEXT NOT NULL UNIQUE REFERENCES scan_patch_proposals(id) ON DELETE CASCADE,
                    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    patch_hash TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS scan_patch_checks (
                    id TEXT PRIMARY KEY,
                    proposal_id TEXT NOT NULL REFERENCES scan_patch_proposals(id) ON DELETE CASCADE,
                    status TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS source_share_consents (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    scan_id TEXT NOT NULL REFERENCES project_scans(id) ON DELETE CASCADE,
                    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    files_json TEXT NOT NULL,
                    model TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    purpose TEXT NOT NULL DEFAULT 'AI_REVIEW'
                );
                CREATE TABLE IF NOT EXISTS candidate_patches (
                    id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                    project_id TEXT REFERENCES projects(id) ON DELETE CASCADE,
                    finding_id TEXT NOT NULL,
                    authoring_source TEXT NOT NULL,
                    patch_format TEXT NOT NULL,
                    patch_hash TEXT NOT NULL,
                    source_revision TEXT NOT NULL,
                    policy_status TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_candidates_finding ON candidate_patches(finding_id, created_at);
                CREATE INDEX IF NOT EXISTS idx_candidates_project ON candidate_patches(project_id, created_at);
                CREATE TABLE IF NOT EXISTS github_pr_bindings (
                    id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                    repo_full_name TEXT NOT NULL,
                    pr_number INTEGER NOT NULL,
                    base_sha TEXT NOT NULL,
                    head_sha TEXT NOT NULL,
                    patch_hash TEXT NOT NULL,
                    commit_status TEXT NOT NULL,
                    status_target_url TEXT,
                    is_stale INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_github_pr_repo ON github_pr_bindings(repo_full_name, pr_number);
                CREATE INDEX IF NOT EXISTS idx_github_pr_job ON github_pr_bindings(job_id);
                CREATE TABLE IF NOT EXISTS github_deliveries (
                    delivery_id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    repo_full_name TEXT NOT NULL,
                    received_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS regression_memory (
                    id TEXT PRIMARY KEY,
                    vulnerability_profile TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    failure_pattern TEXT NOT NULL,
                    sanitized_explanation TEXT NOT NULL,
                    remediation_pattern TEXT NOT NULL,
                    trusted_test_scenarios_json TEXT NOT NULL,
                    historical_limitations TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_regmem_vuln ON regression_memory(vulnerability_profile, file_path);
                CREATE TABLE IF NOT EXISTS verification_timings (
                    id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                    phase TEXT NOT NULL,
                    duration_ms INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_timings_job ON verification_timings(job_id, phase);
            """)
            try:
                columns = {row["name"] for row in db.execute("PRAGMA table_info(approvals)")}
                if "attempt" not in columns:
                    db.execute("ALTER TABLE approvals ADD COLUMN attempt INTEGER")
                    db.execute("""UPDATE approvals SET attempt =
                                  (SELECT attempt FROM patch_proposals WHERE id = approvals.patch_id)""")
                consent_columns = {row["name"] for row in db.execute("PRAGMA table_info(source_share_consents)")}
                if "purpose" not in consent_columns:
                    db.execute("ALTER TABLE source_share_consents ADD COLUMN purpose TEXT NOT NULL DEFAULT 'AI_REVIEW'")
                job_columns = {row["name"] for row in db.execute("PRAGMA table_info(jobs)")}
                if "version" not in job_columns:
                    db.execute("ALTER TABLE jobs ADD COLUMN version INTEGER NOT NULL DEFAULT 0")
                proposal_columns = {row["name"] for row in db.execute("PRAGMA table_info(patch_proposals)")}
                if "authoring_source" not in proposal_columns:
                    db.execute("ALTER TABLE patch_proposals ADD COLUMN authoring_source TEXT NOT NULL DEFAULT 'Ollama (Internal Agent)'")
                attestation_cols = {row["name"] for row in db.execute("PRAGMA table_info(run_attestations)")}
                if "attestation_payload_json" not in attestation_cols:
                    db.execute("ALTER TABLE run_attestations ADD COLUMN attestation_payload_json TEXT")
                if "signature" not in attestation_cols:
                    db.execute("ALTER TABLE run_attestations ADD COLUMN signature TEXT")
                if "key_id" not in attestation_cols:
                    db.execute("ALTER TABLE run_attestations ADD COLUMN key_id TEXT")
                if "signature_algorithm" not in attestation_cols:
                    db.execute("ALTER TABLE run_attestations ADD COLUMN signature_algorithm TEXT")
                if db.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
                    raise RuntimeError("SQLite foreign keys are disabled")
                required = {"job_bindings", "approval_bindings", "verification_leases", "run_attestations"}
                found = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if not required <= found:
                    raise RuntimeError("critical database schema is incomplete")
                critical = {"idx_runs_patch", "workflow_events_no_update", "workflow_events_no_delete"}
                objects = {row[0] for row in db.execute("SELECT name FROM sqlite_master")}
                if not critical <= objects:
                    raise RuntimeError("critical database constraint is missing")
                if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise RuntimeError("database integrity check failed")
                if db.execute("PRAGMA foreign_key_check").fetchone():
                    raise RuntimeError("database foreign key integrity check failed")
                db.commit()
            except Exception:
                db.rollback()
                raise

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        db = self.connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            self._secure_sidecars()
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    @contextmanager
    def read(self) -> Iterator[sqlite3.Connection]:
        db = self.connect()
        try:
            db.execute("BEGIN")
            self._secure_sidecars()
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()
