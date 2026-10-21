"""Automated tests for TestResultEvaluator (Hardened & Adversarial Scenarios)."""

import json
from verification.contracts import VerificationStatus
from verification.evaluator import TestResultEvaluator

ALL_REQUIRED_TEST_NODES = [
    "verification/protected_tests/test_functional.py::test_owner_accesses_own_document_successfully",
    "verification/protected_tests/test_functional.py::test_anonymous_user_cannot_access_private_documents",
    "verification/protected_tests/test_functional.py::test_nonexistent_document_handled_correctly",
    "verification/protected_tests/test_functional.py::test_legitimate_functionality_remains_intact",
    "verification/protected_tests/test_security.py::test_user_a_cannot_access_user_b_document",
    "verification/protected_tests/test_security.py::test_user_b_cannot_access_user_a_document",
    "verification/protected_tests/test_security.py::test_multiple_unauthorized_document_ids_rejected",
    "verification/protected_tests/test_security.py::test_superficial_fix_blocking_only_single_id_rejected",
]


def test_evaluator_handles_timeout():
    result = TestResultEvaluator.evaluate(
        job_id="job-001",
        patch_hash="hash123",
        exit_code=-9,
        raw_output="Timeout",
        duration_ms=5000,
        timed_out=True,
    )
    assert result.status == VerificationStatus.EXECUTION_ERROR.value
    assert "timed out" in result.execution_error


def test_evaluator_handles_runner_crash():
    result = TestResultEvaluator.evaluate(
        job_id="job-001",
        patch_hash="hash123",
        exit_code=137,
        raw_output="OOM",
        runner_error="Container OOMKilled",
    )
    assert result.status == VerificationStatus.EXECUTION_ERROR.value
    assert "OOMKilled" in result.execution_error


def test_evaluator_handles_malformed_report_json():
    result = TestResultEvaluator.evaluate(
        job_id="job-001",
        patch_hash="hash123",
        exit_code=0,
        raw_output="Done",
        report_json_str="Not json {",
    )
    assert result.status == VerificationStatus.EXECUTION_ERROR.value
    assert "Malformed report" in result.execution_error


def test_evaluator_rejects_insufficient_test_collection():
    report = json.dumps({
        "summary": {"total": 3, "passed": 3, "failed": 0, "error": 0},
        "tests": [
            {"nodeid": ALL_REQUIRED_TEST_NODES[0], "outcome": "passed"},
            {"nodeid": ALL_REQUIRED_TEST_NODES[1], "outcome": "passed"},
            {"nodeid": ALL_REQUIRED_TEST_NODES[2], "outcome": "passed"},
        ],
    })
    result = TestResultEvaluator.evaluate(
        job_id="job-001",
        patch_hash="hash123",
        exit_code=0,
        raw_output="3 passed",
        report_json_str=report,
    )
    assert result.status == VerificationStatus.EXECUTION_ERROR.value
    assert "Incomplete test execution" in result.execution_error


def test_evaluator_rejects_missing_required_security_tests():
    # 8 tests passed, but they are all functional/dummy tests without required security tests
    report = json.dumps({
        "summary": {"total": 8, "passed": 8, "failed": 0, "error": 0},
        "tests": [
            {"nodeid": ALL_REQUIRED_TEST_NODES[0], "outcome": "passed"},
            {"nodeid": ALL_REQUIRED_TEST_NODES[1], "outcome": "passed"},
            {"nodeid": ALL_REQUIRED_TEST_NODES[2], "outcome": "passed"},
            {"nodeid": ALL_REQUIRED_TEST_NODES[3], "outcome": "passed"},
            {"nodeid": "dummy_test_1", "outcome": "passed"},
            {"nodeid": "dummy_test_2", "outcome": "passed"},
            {"nodeid": "dummy_test_3", "outcome": "passed"},
            {"nodeid": "dummy_test_4", "outcome": "passed"},
        ],
        "failed_tests": [],
    })
    result = TestResultEvaluator.evaluate(
        job_id="job-001",
        patch_hash="hash123",
        exit_code=0,
        raw_output="8 passed",
        report_json_str=report,
    )
    assert result.status == VerificationStatus.EXECUTION_ERROR.value
    assert "Required protected security test(s) not executed" in result.execution_error


def test_evaluator_detects_exit_code_contradiction():
    # Report claims 8 passed, but exit code is 1 (e.g., crash or assertion after report)
    report = json.dumps({
        "summary": {"total": 8, "passed": 8, "failed": 0, "error": 0},
        "tests": [{"nodeid": node, "outcome": "passed"} for node in ALL_REQUIRED_TEST_NODES],
        "failed_tests": [],
    })
    result = TestResultEvaluator.evaluate(
        job_id="job-001",
        patch_hash="hash123",
        exit_code=1,
        raw_output="Process crashed",
        report_json_str=report,
    )
    assert result.status == VerificationStatus.EXECUTION_ERROR.value
    assert "Exit code contradiction" in result.execution_error


def test_evaluator_detects_summary_tampering():
    # Summary claims 8 passed, but tests array has 7 passed and 1 failed
    report = json.dumps({
        "summary": {"total": 8, "passed": 8, "failed": 0, "error": 0},
        "tests": [
            {"nodeid": node, "outcome": "passed"} for node in ALL_REQUIRED_TEST_NODES[:7]
        ] + [{"nodeid": ALL_REQUIRED_TEST_NODES[7], "outcome": "failed"}],
        "failed_tests": [],
    })
    result = TestResultEvaluator.evaluate(
        job_id="job-001",
        patch_hash="hash123",
        exit_code=0,
        raw_output="Tampered",
        report_json_str=report,
    )
    assert result.status == VerificationStatus.EXECUTION_ERROR.value
    assert "Evidence tampering detected" in result.execution_error


def test_evaluator_returns_verification_failed_on_test_failure():
    report = json.dumps({
        "summary": {"total": 8, "passed": 7, "failed": 1, "error": 0},
        "tests": [
            {"nodeid": ALL_REQUIRED_TEST_NODES[4], "outcome": "failed"},
        ] + [{"nodeid": node, "outcome": "passed"} for node in ALL_REQUIRED_TEST_NODES[:4]]
        + [{"nodeid": node, "outcome": "passed"} for node in ALL_REQUIRED_TEST_NODES[5:]],
        "failed_tests": [ALL_REQUIRED_TEST_NODES[4]],
    })
    result = TestResultEvaluator.evaluate(
        job_id="job-001",
        patch_hash="hash123",
        exit_code=1,
        raw_output="1 failed, 7 passed",
        report_json_str=report,
    )
    assert result.status == VerificationStatus.VERIFICATION_FAILED.value
    assert result.tests_total == 8
    assert result.tests_passed == 7
    assert result.tests_failed == 1
    assert ALL_REQUIRED_TEST_NODES[4] in result.failed_tests
    assert result.execution_error is None


def test_evaluator_returns_verified_when_all_pass():
    report = json.dumps({
        "summary": {"total": 8, "passed": 8, "failed": 0, "error": 0},
        "tests": [{"nodeid": node, "outcome": "passed"} for node in ALL_REQUIRED_TEST_NODES],
        "failed_tests": [],
    })
    result = TestResultEvaluator.evaluate(
        job_id="job-001",
        patch_hash="hash123",
        exit_code=0,
        raw_output="8 passed",
        report_json_str=report,
    )
    assert result.status == VerificationStatus.VERIFIED.value
    assert result.tests_total == 8
    assert result.tests_passed == 8
    assert result.tests_failed == 0
    assert result.failed_tests == []


def test_evaluator_validates_hmac_attestation_signature():
    import hashlib
    import hmac

    token = "secret-orchestrator-run-token-12345"
    patch_hash = "sha256:abc123def456"
    payload = f"8:8:0:0:0:{patch_hash}"
    sig = hmac.new(token.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()

    report = json.dumps({
        "summary": {"total": 8, "passed": 8, "failed": 0, "error": 0},
        "tests": [{"nodeid": node, "outcome": "passed"} for node in ALL_REQUIRED_TEST_NODES],
        "failed_tests": [],
        "exitstatus": 0,
        "attestation": {
            "signature": sig,
            "patch_hash": patch_hash,
            "job_id": "job-001",
        },
    })
    result = TestResultEvaluator.evaluate(
        job_id="job-001",
        patch_hash=patch_hash,
        exit_code=0,
        raw_output="8 passed in 0.5s",
        report_json_str=report,
        run_token=token,
    )
    assert result.status == VerificationStatus.VERIFIED.value
    assert result.tests_passed == 8
    assert result.execution_error is None


def test_evaluator_rejects_missing_hmac_attestation_when_token_required():
    token = "secret-orchestrator-run-token-12345"
    patch_hash = "sha256:abc123def456"
    # Report lacks attestation object
    report = json.dumps({
        "summary": {"total": 8, "passed": 8, "failed": 0, "error": 0},
        "tests": [{"nodeid": node, "outcome": "passed"} for node in ALL_REQUIRED_TEST_NODES],
        "failed_tests": [],
        "exitstatus": 0,
    })
    result = TestResultEvaluator.evaluate(
        job_id="job-001",
        patch_hash=patch_hash,
        exit_code=0,
        raw_output="8 passed in 0.5s",
        report_json_str=report,
        run_token=token,
    )
    assert result.status == VerificationStatus.EXECUTION_ERROR.value
    assert "Missing or invalid cryptographic HMAC attestation" in result.execution_error


def test_evaluator_rejects_forged_hmac_attestation_signature():
    token = "secret-orchestrator-run-token-12345"
    patch_hash = "sha256:abc123def456"
    report = json.dumps({
        "summary": {"total": 8, "passed": 8, "failed": 0, "error": 0},
        "tests": [{"nodeid": node, "outcome": "passed"} for node in ALL_REQUIRED_TEST_NODES],
        "failed_tests": [],
        "exitstatus": 0,
        "attestation": {
            "signature": "forged_invalid_signature_hex_00000000",
            "patch_hash": patch_hash,
            "job_id": "job-001",
        },
    })
    result = TestResultEvaluator.evaluate(
        job_id="job-001",
        patch_hash=patch_hash,
        exit_code=0,
        raw_output="8 passed in 0.5s",
        report_json_str=report,
        run_token=token,
    )
    assert result.status == VerificationStatus.EXECUTION_ERROR.value
    assert "Cryptographic HMAC attestation mismatch" in result.execution_error


def test_evaluator_detects_duplicate_test_nodeid():
    # Attempt to satisfy 8 tests by duplicating the first test 8 times
    report = json.dumps({
        "summary": {"total": 8, "passed": 8, "failed": 0, "error": 0},
        "tests": [{"nodeid": ALL_REQUIRED_TEST_NODES[0], "outcome": "passed"} for _ in range(8)],
        "failed_tests": [],
    })
    result = TestResultEvaluator.evaluate(
        job_id="job-001",
        patch_hash="hash123",
        exit_code=0,
        raw_output="8 passed",
        report_json_str=report,
    )
    assert result.status == VerificationStatus.EXECUTION_ERROR.value
    assert "Duplicate test node ID" in result.execution_error


def test_evaluator_detects_test_nodeid_outside_protected_tests():
    # Attacker crafts tests outside protected_tests directory
    report = json.dumps({
        "summary": {"total": 8, "passed": 8, "failed": 0, "error": 0},
        "tests": [{"nodeid": f"untrusted_external_tests/test.py::test_{i}", "outcome": "passed"} for i in range(8)],
        "failed_tests": [],
    })
    result = TestResultEvaluator.evaluate(
        job_id="job-001",
        patch_hash="hash123",
        exit_code=0,
        raw_output="8 passed",
        report_json_str=report,
    )
    assert result.status == VerificationStatus.EXECUTION_ERROR.value
    assert "outside protected test suite" in result.execution_error


def test_evaluator_detects_stdout_contradiction_when_pytest_did_not_run():
    # Report claims 8 passed, but stdout was empty or fake
    report = json.dumps({
        "summary": {"total": 8, "passed": 8, "failed": 0, "error": 0},
        "tests": [{"nodeid": node, "outcome": "passed"} for node in ALL_REQUIRED_TEST_NODES],
        "failed_tests": [],
    })
    result = TestResultEvaluator.evaluate(
        job_id="job-001",
        patch_hash="hash123",
        exit_code=0,
        raw_output="Process terminated early with fake output",
        report_json_str=report,
    )
    assert result.status == VerificationStatus.EXECUTION_ERROR.value
    assert "Standard output log contradicts reported all-passing status" in result.execution_error

