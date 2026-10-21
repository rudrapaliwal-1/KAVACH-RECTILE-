"""Automated integration tests for Restricted Docker Runner (Phase 5 & 8)."""

import asyncio
from pathlib import Path
import pytest

from verification.contracts import (
    ApprovalVerifier,
    VerificationRequest,
    VerificationStatus,
)
from verification.patch_validator import PatchValidator
from verification.runner import verify_patch

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"
INCOMPLETE_PATCH = (FIXTURES_DIR / "incomplete_patch.diff").read_text(encoding="utf-8")
CORRECT_PATCH = (FIXTURES_DIR / "correct_patch.diff").read_text(encoding="utf-8")


def make_simple_verifier(allowed_hashes_and_approvals: dict[str, str]) -> ApprovalVerifier:
    def _verifier(patch_hash: str, approval_id: str) -> bool:
        expected = allowed_hashes_and_approvals.get(patch_hash)
        return expected is not None and expected == approval_id
    return _verifier


def test_reject_wrong_target_app_id():
    verifier = make_simple_verifier({})
    req = VerificationRequest(
        job_id="job-01",
        target_app_id="invalid-app-id",
        patch_text=CORRECT_PATCH,
        patch_hash="any_hash",
        approval_id="appr-1",
    )
    result = asyncio.run(verify_patch(req, verifier))
    assert result.status == VerificationStatus.POLICY_REJECTED.value
    assert "Unsupported target_app_id" in result.execution_error


def test_reject_hash_mismatch():
    verifier = make_simple_verifier({"correct_hash": "appr-1"})
    req = VerificationRequest(
        job_id="job-02",
        target_app_id="bola-demo-v1",
        patch_text=CORRECT_PATCH,
        patch_hash="wrong_hash_123456",
        approval_id="appr-1",
    )
    result = asyncio.run(verify_patch(req, verifier))
    assert result.status == VerificationStatus.POLICY_REJECTED.value
    assert "Patch hash mismatch" in result.execution_error


def test_reject_unapproved_patch():
    patch_hash = PatchValidator.compute_hash(CORRECT_PATCH)
    verifier = make_simple_verifier({})  # No approval registered
    req = VerificationRequest(
        job_id="job-03",
        target_app_id="bola-demo-v1",
        patch_text=CORRECT_PATCH,
        patch_hash=patch_hash,
        approval_id="unapproved_id",
    )
    result = asyncio.run(verify_patch(req, verifier))
    assert result.status == VerificationStatus.POLICY_REJECTED.value
    assert "Missing or invalid approval" in result.execution_error


def test_reject_protected_file_patch():
    bad_diff = """--- a/protected_tests/test_security.py
+++ b/protected_tests/test_security.py
@@ -1,1 +1,1 @@
+# Tamper
"""
    patch_hash = PatchValidator.compute_hash(bad_diff)
    verifier = make_simple_verifier({patch_hash: "appr-good"})
    req = VerificationRequest(
        job_id="job-04",
        target_app_id="bola-demo-v1",
        patch_text=bad_diff,
        patch_hash=patch_hash,
        approval_id="appr-good",
    )
    result = asyncio.run(verify_patch(req, verifier))
    assert result.status == VerificationStatus.POLICY_REJECTED.value
    assert "protected file" in result.execution_error


@pytest.mark.docker
def test_docker_runner_incomplete_patch_fails_security_tests():
    """Phase 8: Real Docker execution of incomplete patch fixture."""
    patch_hash = PatchValidator.compute_hash(INCOMPLETE_PATCH)
    verifier = make_simple_verifier({patch_hash: "appr-incomplete-01"})
    req = VerificationRequest(
        job_id="job-05",
        target_app_id="bola-demo-v1",
        patch_text=INCOMPLETE_PATCH,
        patch_hash=patch_hash,
        approval_id="appr-incomplete-01",
        timeout_seconds=30,
    )

    result = asyncio.run(verify_patch(req, verifier))
    assert result.status == VerificationStatus.VERIFICATION_FAILED.value
    assert result.tests_total == 8
    assert result.tests_failed > 0
    assert len(result.failed_tests) > 0
    assert result.execution_error is None


@pytest.mark.docker
def test_docker_runner_correct_patch_verifies_successfully():
    """Phase 8: Real Docker execution of correct patch fixture."""
    patch_hash = PatchValidator.compute_hash(CORRECT_PATCH)
    verifier = make_simple_verifier({patch_hash: "appr-correct-01"})
    req = VerificationRequest(
        job_id="job-06",
        target_app_id="bola-demo-v1",
        patch_text=CORRECT_PATCH,
        patch_hash=patch_hash,
        approval_id="appr-correct-01",
        timeout_seconds=30,
    )

    result = asyncio.run(verify_patch(req, verifier))
    assert result.status == VerificationStatus.VERIFIED.value
    assert result.tests_total == 8
    assert result.tests_passed == 8
    assert result.tests_failed == 0
    assert result.failed_tests == []
    assert result.execution_error is None
