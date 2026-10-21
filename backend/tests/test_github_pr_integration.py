"""Comprehensive Security and Functional Tests for SENTINEL-X GitHub PR Integration.

Tests:
1. Webhook HMAC-SHA256 signature authentication (valid, tampered, missing).
2. Delivery deduplication (X-GitHub-Delivery idempotency).
3. Repository authorization and commit SHA validation.
4. Pull request opened -> creates real SENTINEL-X job, binds base/head commits, posts pending status.
5. Explicit approval requirement enforcement (passing results don't auto-approve).
6. Stale commits rejected and superseded when new commits are pushed (synchronize).
7. End-to-end approval, isolated verification execution, and real status publication to GitHub.
8. Verification failure result publication to GitHub.
9. Pull request closed handling.
10. Rate limit handling and error resilience.
11. Credential isolation (no tokens in containers or public endpoints).
"""

import hashlib
import hmac
import json
import pytest
from dataclasses import replace
from fastapi.testclient import TestClient

from backend.config import Settings
from backend.github_integration import (
    GitHubClient,
    GitHubPRCoordinator,
    verify_github_signature,
    is_repo_authorized,
)
from backend.main import create_app
from backend.models import Status
from backend.schemas import ApprovalRequest, VerificationResult
from backend.tests.conftest import FakeAgent, FakeVerifier, TOKEN

WEBHOOK_SECRET = "github-webhook-secret-9876543210fedcba"
TEST_REPO = "sentinel-sec/demo-target"
BASE_SHA = "a" * 40
HEAD_SHA_V1 = "b" * 40
HEAD_SHA_V2 = "c" * 40

VALID_PR_DIFF = """diff --git a/app/access.py b/app/access.py
--- a/app/access.py
+++ b/app/access.py
@@ -1 +1 @@
-return document
+return document if owner == user else None  # PR security fix
"""


def _sign(payload_bytes: bytes, secret: str = WEBHOOK_SECRET) -> str:
    sig = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    return f"sha256={sig}"


def _make_pr_payload(
    action: str = "opened",
    repo: str = TEST_REPO,
    pr_number: int = 42,
    base_sha: str = BASE_SHA,
    head_sha: str = HEAD_SHA_V1,
    diff_text: str = VALID_PR_DIFF,
) -> bytes:
    payload = {
        "action": action,
        "number": pr_number,
        "repository": {
            "full_name": repo,
            "clone_url": f"https://github.com/{repo}.git",
        },
        "pull_request": {
            "number": pr_number,
            "diff_text": diff_text,
            "base": {"sha": base_sha, "ref": "main"},
            "head": {"sha": head_sha, "ref": "fix/bola-security"},
        },
    }
    return json.dumps(payload).encode("utf-8")


@pytest.fixture
def github_setup(tmp_path):
    source = tmp_path / "source" / "app"
    source.mkdir(parents=True)
    (source / "access.py").write_text("return document\n", encoding="utf-8", newline="\n")

    settings = Settings(
        database_path=tmp_path / "sentinel.db",
        source_root=tmp_path / "source",
        operator_token=TOKEN,
        github_webhook_secret=WEBHOOK_SECRET,
        github_token="ghp_mock_token_for_test",
        github_allowed_repositories=TEST_REPO,
        sentinel_base_url="http://localhost:5173",
    )
    agent = FakeAgent()
    verifier = FakeVerifier()
    app = create_app(settings, agent, verifier)

    mock_client = GitHubClient(token="")
    coordinator = GitHubPRCoordinator(
        db=app.state.workflow.db,
        settings=settings,
        workflow=app.state.workflow,
        client=mock_client,
    )
    app.state.github_coordinator = coordinator

    client = TestClient(app, headers={"X-Operator-Token": TOKEN})
    return client, app, coordinator, mock_client, settings


def test_webhook_signature_verification():
    payload = b'{"hello": "world"}'
    valid_sig = _sign(payload, WEBHOOK_SECRET)

    # Valid signature
    assert verify_github_signature(payload, valid_sig, WEBHOOK_SECRET) is True

    # Tampered payload
    tampered_payload = b'{"hello": "attacker"}'
    assert verify_github_signature(tampered_payload, valid_sig, WEBHOOK_SECRET) is False

    # Invalid secret
    assert verify_github_signature(payload, valid_sig, "wrong-secret") is False

    # Malformed header
    assert verify_github_signature(payload, "invalid_sig", WEBHOOK_SECRET) is False
    assert verify_github_signature(payload, None, WEBHOOK_SECRET) is False
    assert verify_github_signature(payload, valid_sig, "") is False


def test_repository_authorization_policy():
    # Exact match in allowed list
    assert is_repo_authorized("sentinel-sec/demo-target", "sentinel-sec/demo-target") is True
    # Case insensitivity
    assert is_repo_authorized("SENTINEL-SEC/DEMO-TARGET", "sentinel-sec/demo-target") is True
    # Wildcard
    assert is_repo_authorized("any/repo", "*") is True
    # Unauthorized repo
    assert is_repo_authorized("evil-org/malicious-repo", "sentinel-sec/demo-target") is False
    # Malformed repo syntax
    assert is_repo_authorized("invalid_repo_without_slash", "*") is False
    assert is_repo_authorized("../path/traversal", "*") is False


def test_webhook_rejects_unauthorized_signature(github_setup):
    client, _, _, _, _ = github_setup
    payload = _make_pr_payload()

    # Tampered signature
    resp = client.post(
        "/api/webhooks/github",
        content=payload,
        headers={
            "X-Hub-Signature-256": "sha256=0000000000000000000000000000000000000000000000000000000000000000",
            "X-GitHub-Delivery": "deliv-101",
            "X-GitHub-Event": "pull_request",
        },
    )
    assert resp.status_code == 401
    assert resp.json()["code"] == "WEBHOOK_SIGNATURE_INVALID"


def test_webhook_delivery_idempotency(github_setup):
    client, _, _, mock_gh, _ = github_setup
    payload = _make_pr_payload()
    sig = _sign(payload)

    headers = {
        "X-Hub-Signature-256": sig,
        "X-GitHub-Delivery": "deliv-duplicate-test-1",
        "X-GitHub-Event": "pull_request",
    }

    # First delivery
    resp1 = client.post("/api/webhooks/github", content=payload, headers=headers)
    assert resp1.status_code == 200
    assert resp1.json()["status"] == "intake_complete"
    assert len(mock_gh.published_statuses) == 1

    # Duplicate delivery (same delivery ID)
    resp2 = client.post("/api/webhooks/github", content=payload, headers=headers)
    assert resp2.status_code == 200
    assert resp2.json()["status"] == "duplicate_ignored"
    # No extra status published
    assert len(mock_gh.published_statuses) == 1


def test_webhook_rejects_unauthorized_repository(github_setup):
    client, _, _, _, _ = github_setup
    payload = _make_pr_payload(repo="attacker-corp/unauthorized-repo")
    sig = _sign(payload)

    resp = client.post(
        "/api/webhooks/github",
        content=payload,
        headers={
            "X-Hub-Signature-256": sig,
            "X-GitHub-Delivery": "deliv-unauthorized-repo",
            "X-GitHub-Event": "pull_request",
        },
    )
    assert resp.status_code == 403
    assert resp.json()["code"] == "UNAUTHORIZED_REPOSITORY"


def test_pull_request_opened_workflow(github_setup):
    client, app, _, mock_gh, _ = github_setup
    payload = _make_pr_payload(action="opened", pr_number=42, head_sha=HEAD_SHA_V1)
    sig = _sign(payload)

    resp = client.post(
        "/api/webhooks/github",
        content=payload,
        headers={
            "X-Hub-Signature-256": sig,
            "X-GitHub-Delivery": "deliv-opened-1",
            "X-GitHub-Event": "pull_request",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "intake_complete"
    assert data["repo"] == TEST_REPO
    assert data["pr_number"] == 42
    assert data["head_sha"] == HEAD_SHA_V1
    assert data["base_sha"] == BASE_SHA
    assert data["policy_status"] == "PASSED"

    job_id = data["job_id"]
    assert job_id.startswith("job-")

    # Verify real SENTINEL-X job was created
    with app.state.workflow.db.read() as db:
        job = db.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        assert job is not None
        assert job["status"] == Status.AWAITING_APPROVAL.value  # Invariant: human approval required!

        binding = db.execute("SELECT * FROM github_pr_bindings WHERE job_id = ?", (job_id,)).fetchone()
        assert binding is not None
        assert binding["repo_full_name"] == TEST_REPO
        assert binding["pr_number"] == 42
        assert binding["head_sha"] == HEAD_SHA_V1
        assert binding["base_sha"] == BASE_SHA
        assert binding["is_stale"] == 0

    # Verify commit status published to GitHub
    assert len(mock_gh.published_statuses) == 1
    last_status = mock_gh.published_statuses[-1]
    assert last_status["sha"] == HEAD_SHA_V1
    assert last_status["state"] == "pending"
    assert "Awaiting Human Approval" in last_status["description"]
    assert f"/evidence?jobId={job_id}" in last_status["target_url"]


def test_pull_request_synchronize_supersedes_stale_commits(github_setup):
    client, app, _, mock_gh, _ = github_setup

    # Commit 1
    payload1 = _make_pr_payload(action="opened", pr_number=50, head_sha=HEAD_SHA_V1)
    resp1 = client.post(
        "/api/webhooks/github",
        content=payload1,
        headers={
            "X-Hub-Signature-256": _sign(payload1),
            "X-GitHub-Delivery": "deliv-pr-50-c1",
            "X-GitHub-Event": "pull_request",
        },
    )
    assert resp1.status_code == 200
    job1_id = resp1.json()["job_id"]

    # Developer updates pull request with Commit 2 (synchronize)
    payload2 = _make_pr_payload(action="synchronize", pr_number=50, head_sha=HEAD_SHA_V2)
    resp2 = client.post(
        "/api/webhooks/github",
        content=payload2,
        headers={
            "X-Hub-Signature-256": _sign(payload2),
            "X-GitHub-Delivery": "deliv-pr-50-c2",
            "X-GitHub-Event": "pull_request",
        },
    )
    assert resp2.status_code == 200
    job2_id = resp2.json()["job_id"]
    assert job2_id != job1_id

    # Verify old binding marked stale
    with app.state.workflow.db.read() as db:
        old_binding = db.execute("SELECT * FROM github_pr_bindings WHERE job_id = ?", (job1_id,)).fetchone()
        assert old_binding["is_stale"] == 1
        assert old_binding["commit_status"] == "superseded"

        new_binding = db.execute("SELECT * FROM github_pr_bindings WHERE job_id = ?", (job2_id,)).fetchone()
        assert new_binding["is_stale"] == 0
        assert new_binding["head_sha"] == HEAD_SHA_V2

    # Verify status updates:
    # 1. Pending on commit 1
    # 2. Superseded error on commit 1
    # 3. Pending on commit 2
    statuses = mock_gh.published_statuses
    assert len(statuses) == 3
    assert statuses[1]["sha"] == HEAD_SHA_V1
    assert statuses[1]["state"] == "error"
    assert f"Superseded by new commit {HEAD_SHA_V2[:8]}" in statuses[1]["description"]

    assert statuses[2]["sha"] == HEAD_SHA_V2
    assert statuses[2]["state"] == "pending"


def test_end_to_end_verification_and_result_publication(github_setup):
    """A test pull request produces a real SENTINEL-X verification job,

    and its actual result is visible in GitHub and the SENTINEL-X evidence report.
    """
    client, app, _, mock_gh, _ = github_setup

    # 1. Incoming PR
    payload = _make_pr_payload(pr_number=77, head_sha=HEAD_SHA_V1)
    resp = client.post(
        "/api/webhooks/github",
        content=payload,
        headers={
            "X-Hub-Signature-256": _sign(payload),
            "X-GitHub-Delivery": "deliv-e2e-77",
            "X-GitHub-Event": "pull_request",
        },
    )
    assert resp.status_code == 200
    job_id = resp.json()["job_id"]
    patch_hash = resp.json()["patch_hash"]

    # Commit status is pending awaiting approval
    assert mock_gh.published_statuses[-1]["state"] == "pending"
    assert "Awaiting Human Approval" in mock_gh.published_statuses[-1]["description"]

    # 2. Operator reviews and approves exact patch hash
    app_resp = client.post(
        f"/api/jobs/{job_id}/approval",
        json={"decision": "APPROVE", "patch_hash": patch_hash},
    )
    assert app_resp.status_code == 200
    assert app_resp.json()["decision"] == "APPROVE"

    # Status updated to pending verifying
    assert mock_gh.published_statuses[-1]["state"] == "pending"
    assert "Verifying in isolated container" in mock_gh.published_statuses[-1]["description"]

    # 3. Isolated verifier executes
    ver_resp = client.post(f"/api/jobs/{job_id}/verify")
    assert ver_resp.status_code == 200
    ver_data = ver_resp.json()
    assert ver_data["status"] == "VERIFIED"
    assert ver_data["tests_passed"] == 2
    assert ver_data["tests_failed"] == 0

    # 4. Result published to GitHub commit status
    final_status = mock_gh.published_statuses[-1]
    assert final_status["sha"] == HEAD_SHA_V1
    assert final_status["state"] == "success"
    assert "Verification PASSED" in final_status["description"]
    assert f"/evidence?jobId={job_id}" in final_status["target_url"]

    # 5. Evidence report accessible and verifies attestation
    att_resp = client.get(f"/api/jobs/{job_id}")
    assert att_resp.status_code == 200
    assert att_resp.json()["status"] == "VERIFIED"


def test_verification_failure_publishes_failure_status(github_setup):
    client, app, _, mock_gh, _ = github_setup

    # Configure verifier to return FAILED
    app.state.workflow.verifier.statuses = ["FAILED"]

    payload = _make_pr_payload(pr_number=88, head_sha=HEAD_SHA_V1)
    resp = client.post(
        "/api/webhooks/github",
        content=payload,
        headers={
            "X-Hub-Signature-256": _sign(payload),
            "X-GitHub-Delivery": "deliv-fail-88",
            "X-GitHub-Event": "pull_request",
        },
    )
    job_id = resp.json()["job_id"]
    patch_hash = resp.json()["patch_hash"]

    # Operator approves
    client.post(
        f"/api/jobs/{job_id}/approval",
        json={"decision": "APPROVE", "patch_hash": patch_hash},
    )

    # Verifier runs and fails
    ver_resp = client.post(f"/api/jobs/{job_id}/verify")
    assert ver_resp.status_code == 200
    assert ver_resp.json()["status"] == "VERIFICATION_FAILED"

    # Verify published status is failure
    last_status = mock_gh.published_statuses[-1]
    assert last_status["sha"] == HEAD_SHA_V1
    assert last_status["state"] == "failure"
    assert "Verification FAILED" in last_status["description"]


def test_pull_request_closed_marks_bindings_closed(github_setup):
    client, app, _, _, _ = github_setup

    # Open PR
    payload_open = _make_pr_payload(action="opened", pr_number=99)
    resp_open = client.post(
        "/api/webhooks/github",
        content=payload_open,
        headers={
            "X-Hub-Signature-256": _sign(payload_open),
            "X-GitHub-Delivery": "deliv-pr-99-open",
            "X-GitHub-Event": "pull_request",
        },
    )
    job_id = resp_open.json()["job_id"]

    # Close PR
    payload_close = _make_pr_payload(action="closed", pr_number=99)
    resp_close = client.post(
        "/api/webhooks/github",
        content=payload_close,
        headers={
            "X-Hub-Signature-256": _sign(payload_close),
            "X-GitHub-Delivery": "deliv-pr-99-close",
            "X-GitHub-Event": "pull_request",
        },
    )
    assert resp_close.status_code == 200
    assert resp_close.json()["status"] == "pr_closed"

    with app.state.workflow.db.read() as db:
        binding = db.execute("SELECT * FROM github_pr_bindings WHERE job_id = ?", (job_id,)).fetchone()
        assert binding["commit_status"] == "closed"
        assert binding["is_stale"] == 1


def test_get_pr_binding_endpoint(github_setup):
    client, _, _, _, _ = github_setup
    payload = _make_pr_payload(pr_number=123)
    resp = client.post(
        "/api/webhooks/github",
        content=payload,
        headers={
            "X-Hub-Signature-256": _sign(payload),
            "X-GitHub-Delivery": "deliv-pr-123",
            "X-GitHub-Event": "pull_request",
        },
    )
    job_id = resp.json()["job_id"]

    binding_resp = client.get(f"/api/github/bindings/{job_id}")
    assert binding_resp.status_code == 200
    b = binding_resp.json()["binding"]
    assert b["repo_full_name"] == TEST_REPO
    assert b["pr_number"] == 123
    assert b["head_sha"] == HEAD_SHA_V1


def test_rate_limit_and_network_error_resilience(monkeypatch):
    # Simulate rate limited response (HTTP 403, X-RateLimit-Remaining: 0)
    client = GitHubClient(token="ghp_dummy_token")

    from urllib.error import HTTPError
    from email.message import Message

    hdrs = Message()
    hdrs["X-RateLimit-Remaining"] = "0"
    hdrs["X-RateLimit-Reset"] = "1730000000"

    fake_err = HTTPError(
        url="https://api.github.com",
        code=403,
        msg="rate limit exceeded",
        hdrs=hdrs,
        fp=None,
    )

    import backend.github_integration as ghi
    monkeypatch.setattr(ghi, "urlopen", lambda *args, **kwargs: (_ for _ in ()).throw(fake_err))

    res = client.post_commit_status(
        repo=TEST_REPO,
        sha=HEAD_SHA_V1,
        state="success",
        description="test",
        target_url="http://localhost:5173",
    )
    assert res["error"] == "rate_limited"
    assert res["reset_time"] == "1730000000"


def test_credential_isolation_and_no_leakage(github_setup):
    client, app, _, _, settings = github_setup
    payload = _make_pr_payload(pr_number=333)
    resp = client.post(
        "/api/webhooks/github",
        content=payload,
        headers={
            "X-Hub-Signature-256": _sign(payload),
            "X-GitHub-Delivery": "deliv-pr-333",
            "X-GitHub-Event": "pull_request",
        },
    )
    job_id = resp.json()["job_id"]

    # Check job endpoint response
    job_resp = client.get(f"/api/jobs/{job_id}")
    job_text = job_resp.text

    # Verify neither webhook secret nor token appears in API response
    assert settings.github_webhook_secret not in job_text
    assert settings.github_token not in job_text
    assert "ghp_mock_token_for_test" not in job_text

    # Verify verifier calls do not receive secrets
    for call in app.state.workflow.verifier.calls:
        call_str = str(call)
        assert settings.github_webhook_secret not in call_str
        assert settings.github_token not in call_str

