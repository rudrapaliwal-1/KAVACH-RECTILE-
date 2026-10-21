from typing import List, Optional
from fastapi import APIRouter, Header, Query, Request

from ..approvals import require_operator
from ..auth import identity_kind, principal
from ..candidates import CandidateLabEngine
from ..schemas import ComparisonReport, PatchIntakeRequest, PatchIntakeResponse


router = APIRouter(tags=["candidates"])


def _get_engine(request: Request) -> CandidateLabEngine:
    workflow = request.app.state.workflow
    return CandidateLabEngine(workflow.db, workflow.settings, workflow)


@router.post("/api/patches/intake", response_model=PatchIntakeResponse)
def intake_patch(
    payload: PatchIntakeRequest,
    request: Request,
    x_operator_token: str | None = Header(default=None),
):
    """Submits a candidate patch from any AI tool or manual source."""
    if identity_kind.get() != "USER_SESSION":
        require_operator(request.app.state.workflow.settings, x_operator_token)
    actor = principal.get() or "system"
    engine = _get_engine(request)
    return engine.intake_candidate_patch(payload, actor_id=actor)


@router.post("/api/jobs/{job_id}/candidates", response_model=PatchIntakeResponse)
def intake_candidate_for_job(
    job_id: str,
    payload: PatchIntakeRequest,
    request: Request,
    x_operator_token: str | None = Header(default=None),
):
    """Submits a candidate patch specifically for an existing remediation job."""
    if identity_kind.get() != "USER_SESSION":
        require_operator(request.app.state.workflow.settings, x_operator_token)
    actor = principal.get() or "system"
    payload_with_job = payload.model_copy(update={"job_id": job_id})
    engine = _get_engine(request)
    return engine.intake_candidate_patch(payload_with_job, actor_id=actor)


@router.get("/api/candidates")
def list_candidates(
    request: Request,
    project_id: Optional[str] = Query(default=None),
    finding_id: Optional[str] = Query(default=None),
):
    """Lists candidate patches with optional project_id or finding_id filters."""
    engine = _get_engine(request)
    return engine.list_candidates(project_id=project_id, finding_id=finding_id)


@router.get("/api/candidates/compare", response_model=ComparisonReport)
def compare_candidates(
    request: Request,
    job_ids: str = Query(..., description="Comma-separated list of candidate job IDs to compare"),
):
    """Normalizes and compares technical verification outcomes across candidate patches."""
    parsed_ids = [j.strip() for j in job_ids.split(",") if j.strip()]
    engine = _get_engine(request)
    return engine.compare_candidates(parsed_ids)
