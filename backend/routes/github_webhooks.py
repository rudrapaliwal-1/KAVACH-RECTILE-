"""FastAPI route handler for incoming GitHub webhooks and PR verification bindings."""

from fastapi import APIRouter, Header, Request, Response
from typing import Optional

from ..github_integration import GitHubPRCoordinator
from ..models import WorkflowError

router = APIRouter(prefix="/api", tags=["github"])


@router.post("/webhooks/github")
async def github_webhook(
    request: Request,
    x_hub_signature_256: Optional[str] = Header(None, alias="X-Hub-Signature-256"),
    x_github_delivery: Optional[str] = Header(None, alias="X-GitHub-Delivery"),
    x_github_event: Optional[str] = Header(None, alias="X-GitHub-Event"),
):
    """Processes incoming authenticated GitHub webhooks for pull requests."""
    raw_payload = await request.body()
    headers = {
        "x-hub-signature-256": x_hub_signature_256 or "",
        "x-github-delivery": x_github_delivery or "",
        "x-github-event": x_github_event or "",
    }

    # Optional custom diff header for testing or bounded direct submission
    custom_diff = request.headers.get("x-sentinel-custom-diff")

    coordinator = getattr(request.app.state, "github_coordinator", None)
    if not coordinator:
        coordinator = GitHubPRCoordinator(
            db=request.app.state.workflow.db,
            settings=request.app.state.workflow.settings,
            workflow=request.app.state.workflow,
        )

    result = coordinator.process_webhook(raw_payload, headers, custom_diff=custom_diff)
    return result


@router.get("/github/bindings/{job_id}")
def get_pr_binding(job_id: str, request: Request):
    """Retrieves GitHub PR binding metadata for a given SENTINEL-X verification job."""
    with request.app.state.workflow.db.read() as db:
        binding = db.execute(
            "SELECT * FROM github_pr_bindings WHERE job_id = ?",
            (job_id,),
        ).fetchone()
        if not binding:
            raise WorkflowError("No GitHub pull request binding for this job", 404, "BINDING_NOT_FOUND")
        return {"binding": dict(binding)}
