from fastapi import APIRouter, Header, Request

from ..approvals import require_operator
from ..auth import identity_kind


router = APIRouter(prefix="/api/jobs", tags=["verification"])


@router.post("/{job_id}/verify")
def verify(job_id: str, request: Request,
           x_operator_token: str | None = Header(default=None)):
    if identity_kind.get() != "USER_SESSION":
        require_operator(request.app.state.workflow.settings, x_operator_token)
    result = request.app.state.workflow.verify(job_id)
    coordinator = getattr(request.app.state, "github_coordinator", None)
    if coordinator:
        try:
            coordinator.sync_job_status_to_github(job_id)
        except Exception:
            pass
    return result


@router.post("/{job_id}/mutation-test")
def run_mutation_test(job_id: str, request: Request,
                      x_operator_token: str | None = Header(default=None)):
    if identity_kind.get() != "USER_SESSION":
        require_operator(request.app.state.workflow.settings, x_operator_token)
    return request.app.state.workflow.run_mutation_testing(job_id)
