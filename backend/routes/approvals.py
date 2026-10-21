from fastapi import APIRouter, Header, Request

from ..schemas import ApprovalRequest


router = APIRouter(prefix="/api/jobs", tags=["approvals"])


@router.post("/{job_id}/approval")
def decide_approval(job_id: str, payload: ApprovalRequest, request: Request,
                    x_operator_token: str | None = Header(default=None)):
    result = request.app.state.workflow.decide(job_id, payload, x_operator_token)
    coordinator = getattr(request.app.state, "github_coordinator", None)
    if coordinator:
        try:
            coordinator.sync_job_status_to_github(job_id)
        except Exception:
            pass
    return result
