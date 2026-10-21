"""VibeCI endpoints for fast preflight and multi-layer verification."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, List, Optional
from uuid import uuid4

from fastapi import APIRouter, Header, Query, Request
from pydantic import BaseModel, Field

from ..auth import current_user, identity_kind
from ..database import utc_now
from ..models import WorkflowError
from ..security_activity import record
from ..services.vibeci_service import VibeCIOptions, VibeCIService, validate_contained_path
from .projects import _project, _source_dir

router = APIRouter(prefix="/api", tags=["vibeci"])
service = VibeCIService()


class VibeCIVerifyPayload(BaseModel):
    run_static: bool = True
    run_build: bool = False
    run_tests: bool = True
    run_smoke: bool = False
    changed_only: bool = False
    compare_ref: Optional[str] = None
    fail_fast: bool = False
    timeout_seconds: int = Field(default=30, ge=1, le=120)


class VibeCIRulePayload(BaseModel):
    agent: str = Field(default="all", pattern=r"^(all|cursor|claude|copilot|universal|antigravity)$")


@router.get("/vibeci/status")
def vibeci_status():
    """Return vibeCI integration status, available verification layers, and detected host tools."""
    return service.get_status()


@router.post("/projects/{project_id}/vibeci/preflight", status_code=200)
def run_preflight(project_id: str, request: Request):
    """Run fast, sub-second preflight audit: secret scanning, environment preflight,

    platform limits, and honest boundary accounting.
    """
    _project(request, project_id)
    root = _source_dir(request, project_id)
    if not root.is_dir() or root.is_symlink():
        raise WorkflowError("project source is unavailable", 409, "SOURCE_UNAVAILABLE")

    report = service.run_preflight_audit(root)
    run_id = "vbr-" + uuid4().hex
    now = utc_now()
    summary = report.summary
    report_dict = report.to_dict()

    with request.app.state.workflow.db.transaction() as db:
        db.execute(
            """INSERT INTO vibeci_runs (
                id, project_id, run_type, status, overall_status, duration_ms,
                checks_total, checks_passed, checks_failed, checks_warnings, checks_unverified,
                report_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                project_id,
                "PREFLIGHT",
                report.status.value,
                report.status.value,
                report.total_duration_ms,
                summary["total"],
                summary["passed"],
                summary["failed"],
                summary["warnings"],
                summary["not_checked"],
                json.dumps(report_dict),
                now,
            ),
        )
        record(db, project_id, "VIBECI_PREFLIGHT_COMPLETED", run_id, report.status.value)

    return {
        "run_id": run_id,
        "project_id": project_id,
        "run_type": "PREFLIGHT",
        **report_dict,
        "created_at": now,
    }


@router.post("/projects/{project_id}/vibeci/verify", status_code=200)
def run_verification(project_id: str, payload: VibeCIVerifyPayload, request: Request):
    """Execute multi-layer verification on the project source."""
    _project(request, project_id)
    root = _source_dir(request, project_id)
    if not root.is_dir() or root.is_symlink():
        raise WorkflowError("project source is unavailable", 409, "SOURCE_UNAVAILABLE")

    opts = VibeCIOptions(
        run_static=payload.run_static,
        run_build=payload.run_build,
        run_tests=payload.run_tests,
        run_smoke=payload.run_smoke,
        changed_only=payload.changed_only,
        compare_ref=payload.compare_ref,
        fail_fast=payload.fail_fast,
        timeout_seconds=payload.timeout_seconds,
    )

    report = service.run_verification(root, options=opts)
    run_id = "vbr-" + uuid4().hex
    now = utc_now()
    summary = report.summary
    report_dict = report.to_dict()

    with request.app.state.workflow.db.transaction() as db:
        db.execute(
            """INSERT INTO vibeci_runs (
                id, project_id, run_type, status, overall_status, duration_ms,
                checks_total, checks_passed, checks_failed, checks_warnings, checks_unverified,
                report_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                project_id,
                "VERIFICATION",
                report.status.value,
                report.status.value,
                report.total_duration_ms,
                summary["total"],
                summary["passed"],
                summary["failed"],
                summary["warnings"],
                summary["not_checked"],
                json.dumps(report_dict),
                now,
            ),
        )
        record(db, project_id, "VIBECI_VERIFICATION_COMPLETED", run_id, report.status.value)

    return {
        "run_id": run_id,
        "project_id": project_id,
        "run_type": "VERIFICATION",
        **report_dict,
        "created_at": now,
    }


@router.get("/projects/{project_id}/vibeci/reports")
def list_reports(project_id: str, request: Request):
    """Retrieve historical vibeCI execution reports for the project."""
    _project(request, project_id)
    with request.app.state.workflow.db.read() as db:
        rows = db.execute(
            """SELECT id, project_id, run_type, status, overall_status, duration_ms,
                      checks_total, checks_passed, checks_failed, checks_warnings, checks_unverified,
                      created_at
               FROM vibeci_runs WHERE project_id = ? ORDER BY created_at DESC LIMIT 50""",
            (project_id,),
        ).fetchall()
        return [dict(r) for r in rows]


@router.get("/projects/{project_id}/vibeci/reports/{run_id}")
def get_report(project_id: str, run_id: str, request: Request):
    """Retrieve full details and raw structured results for a specific vibeCI run."""
    _project(request, project_id)
    with request.app.state.workflow.db.read() as db:
        row = db.execute(
            "SELECT * FROM vibeci_runs WHERE id = ? AND project_id = ?",
            (run_id, project_id),
        ).fetchone()
        if not row:
            raise WorkflowError("verification report not found", 404, "REPORT_NOT_FOUND")
        item = dict(row)
        item["report"] = json.loads(item.pop("report_json"))
        return item


@router.get("/projects/{project_id}/vibeci/rules")
def get_rules(project_id: str, request: Request):
    """Inspect configured AI coding rules in the project."""
    _project(request, project_id)
    root = _source_dir(request, project_id)
    if not root.is_dir():
        raise WorkflowError("project source is unavailable", 409, "SOURCE_UNAVAILABLE")
    return service.get_agent_rules(root)


@router.post("/projects/{project_id}/vibeci/rules", status_code=200)
def configure_rules(project_id: str, payload: VibeCIRulePayload, request: Request):
    """Install or update AI coding assistant instructions for vibeCI."""
    _project(request, project_id)
    root = _source_dir(request, project_id)
    if not root.is_dir():
        raise WorkflowError("project source is unavailable", 409, "SOURCE_UNAVAILABLE")
    res = service.install_agent_rules(root, agent=payload.agent)
    with request.app.state.workflow.db.transaction() as db:
        record(db, project_id, "VIBECI_RULES_CONFIGURED", project_id, payload.agent)
    return res
