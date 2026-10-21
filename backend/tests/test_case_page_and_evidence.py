import hashlib
import json
import pytest
from fastapi.testclient import TestClient

from backend.config import Settings
from backend.main import create_app
from backend.policy import patch_hash
from backend.schemas import AgentProposal, VerificationResult


TOKEN = "test-operator-token-case-page-123456789"
PATCH_V1 = """diff --git a/app/access.py b/app/access.py
--- a/app/access.py
+++ b/app/access.py
@@ -1 +1 @@
-return document
+return document if owner else None  # attempt 0
"""
PATCH_V2 = """diff --git a/app/access.py b/app/access.py
--- a/app/access.py
+++ b/app/access.py
@@ -1 +1 @@
-return document
+return document if owner == requesting_user_id else None  # attempt 1
"""


class MultiAttemptAgent:
    def __init__(self):
        self.proposals = [PATCH_V1, PATCH_V2]
        self.calls = []

    def propose_patch(self, finding, source_context, attempt, feedback=None):
        self.calls.append((attempt, feedback))
        text = self.proposals[min(attempt, len(self.proposals) - 1)]
        return AgentProposal(
            root_cause="Missing ownership check on document access",
            explanation=f"Fixed ownership check on attempt {attempt}",
            patch_format="unified_diff",
            patch_text=text,
            files_changed=["app/access.py"],
        )


class ConfigurableVerifier:
    def __init__(self, outcomes=None):
        # outcomes: list of ("PASSED" | "FAILED" | "EXECUTION_ERROR", test_results)
        self.outcomes = list(outcomes or [("PASSED", [
            {"name": "test_access_owner_success", "outcome": "passed"},
            {"name": "test_access_other_user_denied", "outcome": "passed"},
        ])])
        self.calls = []

    def verify_patch(self, request, approval_verifier):
        assert approval_verifier(request.job_id, request.patch_id,
                                 request.patch_hash, request.approval_id)
        self.calls.append(request)
        status, test_results = self.outcomes.pop(0)
        passed = sum(1 for t in test_results if t["outcome"] == "passed")
        failed = sum(1 for t in test_results if t["outcome"] == "failed")
        return VerificationResult(
            status=status,
            tests_total=len(test_results),
            tests_passed=passed,
            tests_failed=failed,
            failed_tests=[t["name"] for t in test_results if t["outcome"] == "failed"],
            test_results=test_results,
            duration_ms=42,
            test_suite_id=request.verification_profile,
            tests_collected=len(test_results),
            collection_complete=True,
            execution_completed=True,
            run_id=request.run_id,
            patch_hash=request.patch_hash,
            source_revision=request.source_revision,
            verification_profile=request.verification_profile,
        )


@pytest.fixture
def case_app(tmp_path):
    source = tmp_path / "source" / "app"
    source.mkdir(parents=True)
    source_content = "def get_document(user, doc_id):\n    return document\n"
    (source / "access.py").write_text(source_content, encoding="utf-8", newline="\n")
    settings = Settings(
        database_path=tmp_path / "case_test.db",
        source_root=tmp_path / "source",
        operator_token=TOKEN,
    )
    agent = MultiAttemptAgent()
    verifier = ConfigurableVerifier()
    app = create_app(settings, agent, verifier)
    client = TestClient(app, headers={"X-Operator-Token": TOKEN})
    return client, agent, verifier, settings, source_content


@pytest.fixture
def finding_payload():
    return {
        "target_app_id": "bola-demo-v1",
        "finding": {
            "id": "BOLA-CASE-001",
            "type": "BROKEN_OBJECT_LEVEL_AUTHORIZATION",
            "severity": "HIGH",
            "file_path": "app/access.py",
            "description": "The document access endpoint fails to verify document ownership.",
        },
    }


def test_source_endpoint_and_case_details(case_app, finding_payload):
    client, agent, verifier, settings, source_content = case_app
    res = client.post("/api/findings", json=finding_payload)
    assert res.status_code == 202
    job_id = res.json()["job_id"]

    # 1. Source endpoint delivers vulnerable code
    source_res = client.get(f"/api/jobs/{job_id}/source")
    assert source_res.status_code == 200
    source_data = source_res.json()
    assert source_data["job_id"] == job_id
    assert source_data["file_path"] == "app/access.py"
    assert source_data["content"] == source_content
    assert source_data["source_revision"] is not None

    # Missing job gives 404
    assert client.get("/api/jobs/job-nonexistent/source").status_code == 404

    # 2. Patch details
    patch_res = client.get(f"/api/jobs/{job_id}/patch")
    assert patch_res.status_code == 200
    patch = patch_res.json()
    assert patch["attempt"] == 0
    assert patch["patch_hash"] == patch_hash(PATCH_V1)
    assert "Missing ownership check" in patch["root_cause"]


def test_exact_hash_binding_and_rejection_of_tampered_hash(case_app, finding_payload):
    client, _, _, settings, _ = case_app
    job_id = client.post("/api/findings", json=finding_payload).json()["job_id"]
    patch = client.get(f"/api/jobs/{job_id}/patch").json()
    canonical_hash = patch["patch_hash"]

    # Attempting to approve with altered/wrong hash must fail with 409
    tampered_hash = "sha256:" + "0" * 64
    bad_approval = client.post(f"/api/jobs/{job_id}/approval", json={
        "patch_hash": tampered_hash,
        "decision": "APPROVE",
    })
    assert bad_approval.status_code == 409
    assert "PATCH_HASH_MISMATCH" in bad_approval.json().get("code", "")

    # Approving with exact canonical hash succeeds
    good_approval = client.post(f"/api/jobs/{job_id}/approval", json={
        "patch_hash": canonical_hash,
        "decision": "APPROVE",
    })
    assert good_approval.status_code == 200
    approval_data = good_approval.json()
    assert approval_data["patch_hash"] == canonical_hash
    assert approval_data["decision"] == "APPROVE"
    assert approval_data["approved_by"] == settings.operator_name


def test_revision_requires_fresh_approval(tmp_path, finding_payload):
    source = tmp_path / "source" / "app"
    source.mkdir(parents=True)
    (source / "access.py").write_text("return document\n", encoding="utf-8", newline="\n")
    settings = Settings(database_path=tmp_path / "rev_test.db", source_root=tmp_path / "source", operator_token=TOKEN)
    agent = MultiAttemptAgent()
    # First run fails tests, second run passes tests
    verifier = ConfigurableVerifier([
        ("FAILED", [
            {"name": "test_access_owner_success", "outcome": "passed"},
            {"name": "test_access_other_user_denied", "outcome": "failed"},
        ]),
        ("PASSED", [
            {"name": "test_access_owner_success", "outcome": "passed"},
            {"name": "test_access_other_user_denied", "outcome": "passed"},
        ]),
    ])
    app = create_app(settings, agent, verifier)
    client = TestClient(app, headers={"X-Operator-Token": TOKEN})

    # Start finding -> attempt 0
    job_id = client.post("/api/findings", json=finding_payload).json()["job_id"]
    patch_0 = client.get(f"/api/jobs/{job_id}/patch").json()
    assert patch_0["attempt"] == 0

    # Approve attempt 0
    client.post(f"/api/jobs/{job_id}/approval", json={"patch_hash": patch_0["patch_hash"], "decision": "APPROVE"})

    # Verify attempt 0 -> fails
    v0_res = client.post(f"/api/jobs/{job_id}/verify")
    assert v0_res.status_code == 200
    assert v0_res.json()["status"] == "VERIFICATION_FAILED"
    assert v0_res.json()["tests_failed"] == 1

    # Backend automatically transitions to attempt 1 with reflection guidance
    patch_1 = client.get(f"/api/jobs/{job_id}/patch").json()
    assert patch_1["attempt"] == 1
    assert patch_1["patch_hash"] != patch_0["patch_hash"]

    # Calling verify BEFORE fresh approval must fail!
    premature_verify = client.post(f"/api/jobs/{job_id}/verify")
    assert premature_verify.status_code == 409
    assert premature_verify.json().get("code") in ("APPROVAL_REQUIRED", "INVALID_TRANSITION", "WORKFLOW_ERROR")

    # Stale approval of attempt 0's hash for attempt 1 must fail!
    stale_approval = client.post(f"/api/jobs/{job_id}/approval", json={
        "patch_hash": patch_0["patch_hash"],
        "decision": "APPROVE",
    })
    assert stale_approval.status_code == 409

    # Fresh approval of attempt 1's exact hash succeeds
    fresh_approval = client.post(f"/api/jobs/{job_id}/approval", json={
        "patch_hash": patch_1["patch_hash"],
        "decision": "APPROVE",
    })
    assert fresh_approval.status_code == 200

    # Now verification of attempt 1 succeeds
    v1_res = client.post(f"/api/jobs/{job_id}/verify")
    assert v1_res.status_code == 200
    assert v1_res.json()["status"] == "VERIFIED"

    # Evidence reflects both runs and individual test results
    evidence = client.get(f"/api/jobs/{job_id}/evidence").json()
    assert evidence["conclusion"] == "VERIFIED"
    assert len(evidence["verification_runs"]) == 2
    assert evidence["verification_runs"][0]["status"] == "VERIFICATION_FAILED"
    assert evidence["verification_runs"][1]["status"] == "VERIFIED"
    # Individual real test results are preserved in evidence
    run_1_results = evidence["verification_runs"][1]["result"]["test_results"]
    assert len(run_1_results) == 2
    assert all(t["outcome"] == "passed" for t in run_1_results)


def test_jobs_pagination(case_app, finding_payload):
    client, _, _, _, _ = case_app
    # Create 3 jobs
    for i in range(3):
        payload = {
            "target_app_id": "bola-demo-v1",
            "finding": {
                "id": f"BOLA-PAGINATION-{i}",
                "type": "BROKEN_OBJECT_LEVEL_AUTHORIZATION",
                "severity": "HIGH",
                "file_path": "app/access.py",
                "description": f"Finding number {i}",
            },
        }
        client.post("/api/findings", json=payload)

    # Test limit=2, offset=0
    page1 = client.get("/api/jobs?limit=2&offset=0").json()
    assert len(page1) == 2

    # Test limit=2, offset=2
    page2 = client.get("/api/jobs?limit=2&offset=2").json()
    assert len(page2) >= 1
    assert page1[0]["id"] != page2[0]["id"]


def test_duplicate_verification_prevention(case_app, finding_payload):
    client, _, verifier, _, _ = case_app
    job_id = client.post("/api/findings", json=finding_payload).json()["job_id"]
    patch = client.get(f"/api/jobs/{job_id}/patch").json()
    client.post(f"/api/jobs/{job_id}/approval", json={"patch_hash": patch["patch_hash"], "decision": "APPROVE"})

    # First verify call succeeds
    res1 = client.post(f"/api/jobs/{job_id}/verify")
    assert res1.status_code == 200

    # Second verify call on already verified job is blocked with 409
    res2 = client.post(f"/api/jobs/{job_id}/verify")
    assert res2.status_code == 409


def test_complete_evidence_integrity(case_app, finding_payload):
    client, _, _, _, _ = case_app
    job_id = client.post("/api/findings", json=finding_payload).json()["job_id"]
    patch = client.get(f"/api/jobs/{job_id}/patch").json()
    client.post(f"/api/jobs/{job_id}/approval", json={"patch_hash": patch["patch_hash"], "decision": "APPROVE"})
    client.post(f"/api/jobs/{job_id}/verify")

    evidence = client.get(f"/api/jobs/{job_id}/evidence").json()
    assert evidence["job_id"] == job_id
    assert evidence["conclusion"] == "VERIFIED"
    assert evidence["source_revision_current"] is True
    assert evidence["target_binding"]["source_revision"] is not None
    assert len(evidence["patch_attempts"]) >= 1
    assert len(evidence["approvals"]) >= 1
    assert len(evidence["verification_runs"]) >= 1
    assert evidence["verification_runs"][0]["attestation_integrity"] == "VALID"
    assert len(evidence["integrity_issues"]) == 0
    assert len(evidence["limitations"]) > 0


def test_verifier_execution_error_handling(tmp_path, finding_payload):
    source = tmp_path / "source" / "app"
    source.mkdir(parents=True)
    (source / "access.py").write_text("return document\n", encoding="utf-8", newline="\n")
    settings = Settings(database_path=tmp_path / "err_test.db", source_root=tmp_path / "source", operator_token=TOKEN)
    agent = MultiAttemptAgent()
    # Verifier reports execution error
    verifier = ConfigurableVerifier([
        ("EXECUTION_ERROR", []),
    ])
    app = create_app(settings, agent, verifier)
    client = TestClient(app, headers={"X-Operator-Token": TOKEN})

    job_id = client.post("/api/findings", json=finding_payload).json()["job_id"]
    patch = client.get(f"/api/jobs/{job_id}/patch").json()
    client.post(f"/api/jobs/{job_id}/approval", json={"patch_hash": patch["patch_hash"], "decision": "APPROVE"})

    verify_res = client.post(f"/api/jobs/{job_id}/verify")
    assert verify_res.status_code == 200
    assert verify_res.json()["status"] == "EXECUTION_ERROR"

    job = client.get(f"/api/jobs/{job_id}").json()
    assert job["status"] == "EXECUTION_ERROR"

    evidence = client.get(f"/api/jobs/{job_id}/evidence").json()
    assert evidence["conclusion"] == "NOT_VERIFIED"
    assert len(evidence["failure_history"]) == 1
