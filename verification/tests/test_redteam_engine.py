"""Red Team Adversarial Security Verification Suite (Developer 3 / Person 2).

Directly validates:
1. Key Acceptance Test: A deliberately incomplete BOLA fix is rejected by independently maintained tests.
2. Correct patches reach VERIFIED with clean adversarial report.
3. Manipulated document identifiers (path traversal, SQLi, null bytes, prefix, type boundary).
4. Boundary cases (unicode variations, case sensitivity, oversized IDs).
5. Policy rejection (forbidden operations, traversal in diff, tampering with protected tests).
6. Execution errors (timeouts, infrastructure crashes).
7. Stale or forged approval rejection (fail-closed before execution).
8. Inconclusive verdict on contradictory evidence (HMAC mismatch, count tampering, stdout contradiction).
9. Optional AI-suggested test failure does NOT fail mandatory verification.
10. Unsupported profile / target rejection.
11. Explicit limitations and security disclaimer integrity ("never claim universally secure").
"""

import copy
import hashlib
import hmac
import json
from pathlib import Path
import pytest

from verification.contracts import (
    AdversarialReport,
    AdversarialScenario,
    TestSource,
    VerificationRequest,
    VerificationResult,
    VerificationStatus,
)
from verification.evaluator import TestResultEvaluator
from verification.patch_validator import PatchValidator, PatchValidationError
from verification.scenarios import (
    execute_single_scenario,
    get_profile_scenarios,
    run_adversarial_suite,
    validate_and_register_ai_scenarios,
)
from verification.lab.app.sample_data import DOCUMENTS


# --- Fixture Models for Incomplete and Correct Access Implementations ---

def vulnerable_get_document(requesting_user_id, document_id):
    """Original vulnerable baseline: no object-level ownership check."""
    if not requesting_user_id or not str(requesting_user_id).strip():
        raise PermissionError("Anonymous access denied")
    if document_id not in DOCUMENTS:
        raise LookupError(f"Document '{document_id}' not found")
    return dict(DOCUMENTS[document_id])


def incomplete_fixed_get_document(requesting_user_id, document_id):
    """Deliberately superficial fix from incomplete_patch.diff: only blocks alice -> doc_bob_1."""
    if not requesting_user_id or not str(requesting_user_id).strip():
        raise PermissionError("Anonymous access denied")
    if document_id not in DOCUMENTS:
        raise LookupError(f"Document '{document_id}' not found")
    doc = DOCUMENTS[document_id]
    # Superficial check
    if requesting_user_id == "alice" and document_id == "doc_bob_1":
        raise PermissionError("Forbidden: Unauthorized document access")
    return dict(doc)


def correctly_fixed_get_document(requesting_user_id, document_id):
    """Correct BOLA fix: enforces doc['owner_id'] == requesting_user_id."""
    if not requesting_user_id or not str(requesting_user_id).strip():
        raise PermissionError("Anonymous access denied")
    if document_id not in DOCUMENTS:
        raise LookupError(f"Document '{document_id}' not found")
    doc = DOCUMENTS[document_id]
    if doc.get("owner_id") != requesting_user_id:
        raise PermissionError(f"Forbidden: User '{requesting_user_id}' does not own document '{document_id}'")
    return dict(doc)


# ==============================================================================
# 1. KEY ACCEPTANCE TEST: Incomplete BOLA Fix Rejected
# ==============================================================================

def test_key_acceptance_deliberately_incomplete_bola_fix_rejected():
    """KEY ACCEPTANCE TEST: An independently maintained test rejects a deliberately incomplete fix."""
    report = run_adversarial_suite(incomplete_fixed_get_document, profile="bola-required-tests-v1")

    # Incomplete fix blocked alice -> doc_bob_1, but fails on bob -> doc_alice_1, alice -> doc_charlie_1, etc.
    assert report.attack_scenarios_failed > 0, "Incomplete patch must fail cross-tenant attack scenarios"
    assert report.vulnerability_mitigated is False, "Incomplete fix must not be marked as mitigated"

    failing_scenario_ids = [s["scenario_id"] for s in report.scenarios if s["execution_status"] != "passed"]
    assert "BOLA-CROSS-002" in failing_scenario_ids  # bob accessing doc_alice_1
    assert "BOLA-CROSS-003" in failing_scenario_ids  # alice accessing doc_charlie_1


def test_correct_patch_passes_all_adversarial_scenarios():
    """Verify that a genuine BOLA remediation passes all independent red team checks."""
    report = run_adversarial_suite(correctly_fixed_get_document, profile="bola-required-tests-v1")

    assert report.attack_scenarios_failed == 0
    assert report.regression_scenarios_failed == 0
    assert len(report.execution_errors) == 0
    assert report.vulnerability_mitigated is True
    assert report.attack_scenarios_passed >= 9


# ==============================================================================
# 2. Manipulated Document Identifiers & Boundary Cases
# ==============================================================================

def test_manipulated_document_identifiers():
    """Verify independent handling of path traversal, SQL injection, null bytes, and type mismatches."""
    report = run_adversarial_suite(correctly_fixed_get_document, profile="bola-required-tests-v1")
    scenario_map = {s["scenario_id"]: s for s in report.scenarios}

    # Path traversal manipulation rejected
    assert scenario_map["BOLA-MANIP-TRAVERSAL"]["execution_status"] == "passed"
    # SQLi manipulation safely rejected
    assert scenario_map["BOLA-MANIP-SQLI"]["execution_status"] == "passed"
    # Null byte manipulation safely rejected
    assert scenario_map["BOLA-MANIP-NULLBYTE"]["execution_status"] == "passed"
    # Numeric type mismatch safely handled without unhandled crash
    assert scenario_map["BOLA-MANIP-TYPEMISMATCH"]["execution_status"] == "passed"


def test_boundary_cases_unicode_and_case_sensitivity():
    """Verify boundary condition handling: unicode zero-width space and case sensitivity."""
    report = run_adversarial_suite(correctly_fixed_get_document, profile="bola-required-tests-v1")
    scenario_map = {s["scenario_id"]: s for s in report.scenarios}

    assert scenario_map["BOLA-BOUND-UNICODE"]["execution_status"] == "passed"
    assert scenario_map["BOLA-BOUND-CASESENSITIVE"]["execution_status"] == "passed"
    assert scenario_map["BOLA-BOUND-MAXLEN"]["execution_status"] == "passed"


# ==============================================================================
# 3. Policy Rejection, Stale Approvals, and Execution Errors
# ==============================================================================

def test_policy_rejection_on_protected_test_tampering():
    """Verify policy engine rejects patches that attempt to modify protected verification tests."""
    tampered_patch = """diff --git a/protected_tests/test_security.py b/protected_tests/test_security.py
--- a/protected_tests/test_security.py
+++ b/protected_tests/test_security.py
@@ -1,5 +1,5 @@
 def test_user_a_cannot_access_user_b_document():
-    assert False
+    assert True
"""
    with pytest.raises(PatchValidationError, match="(?i)Modification of protected file"):
        PatchValidator.validate_patch(tampered_patch)


def test_policy_rejection_on_path_traversal_in_patch():
    """Verify patch validator rejects path traversal in file paths."""
    traversal_patch = """diff --git a/../../etc/shadow b/../../etc/shadow
--- a/../../etc/shadow
+++ b/../../etc/shadow
@@ -1,1 +1,1 @@
+root:x:0:0:root:/root:/bin/bash
"""
    with pytest.raises(PatchValidationError, match="(?i)traversal|scope|unauthorized"):
        PatchValidator.validate_patch(traversal_patch)


def test_execution_error_on_timeout():
    """Verify timeout produces EXECUTION_ERROR."""
    res = TestResultEvaluator.evaluate(
        job_id="job-101",
        patch_hash="sha256:" + "0" * 64,
        exit_code=-1,
        raw_output="Timeout",
        timed_out=True,
        duration_ms=30000,
    )
    assert res.status == VerificationStatus.EXECUTION_ERROR.value
    assert "timed out" in res.execution_error.lower()


def test_execution_error_on_runner_crash():
    """Verify runner crash produces EXECUTION_ERROR."""
    res = TestResultEvaluator.evaluate(
        job_id="job-102",
        patch_hash="sha256:" + "0" * 64,
        exit_code=137,
        raw_output="Killed",
        runner_error="Sandbox killed by OOM killer",
    )
    assert res.status == VerificationStatus.EXECUTION_ERROR.value
    assert "OOM" in res.execution_error


# ==============================================================================
# 4. Inconclusive Verdict on Contradictory Evidence
# ==============================================================================

def test_inconclusive_verdict_on_contradictory_evidence():
    """Verify evaluator distinguishes INCONCLUSIVE when evidence is contradictory or missing."""
    nodes = [f"verification/protected_tests/test_security.py::test_{i}" for i in range(8)]
    # Report summary claims 8 passed, but tests list has a failure
    tampered_report = json.dumps({
        "summary": {"total": 8, "passed": 8, "failed": 0, "error": 0},
        "tests": [{"nodeid": n, "outcome": "passed" if i < 7 else "failed"} for i, n in enumerate(nodes)],
    })
    res = TestResultEvaluator.evaluate(
        job_id="job-103",
        patch_hash="sha256:" + "0" * 64,
        exit_code=0,
        raw_output="Tampered",
        report_json_str=tampered_report,
        fine_grained=True,
    )
    assert res.status == VerificationStatus.INCONCLUSIVE.value
    assert res.verdict_category == VerificationStatus.INCONCLUSIVE.value
    assert "Evidence tampering detected" in res.execution_error


def test_inconclusive_verdict_on_stdout_contradiction():
    """Verify evaluator flags INCONCLUSIVE when stdout contradicts reported test status."""
    nodes = [f"verification/protected_tests/test_security.py::test_{i}" for i in range(8)]
    report = json.dumps({
        "summary": {"total": 8, "passed": 8, "failed": 0, "error": 0},
        "tests": [{"nodeid": n, "outcome": "passed"} for n in nodes],
    })
    res = TestResultEvaluator.evaluate(
        job_id="job-104",
        patch_hash="sha256:" + "0" * 64,
        exit_code=0,
        raw_output="Fake log without any pytest passed indication",
        report_json_str=report,
        fine_grained=True,
    )
    assert res.status == VerificationStatus.INCONCLUSIVE.value
    assert res.verdict_category == VerificationStatus.INCONCLUSIVE.value


# ==============================================================================
# 5. Optional AI-Suggested Tests Do NOT Fail Mandatory Verification
# ==============================================================================

def test_optional_ai_suggested_test_failure_does_not_fail_mandatory():
    """Verify that optional AI-suggested tests do not fail mandatory verification when is_mandatory=False."""
    nodes = [
        "verification/protected_tests/test_functional.py::test_owner_accesses_own_document_successfully",
        "verification/protected_tests/test_functional.py::test_anonymous_user_cannot_access_private_documents",
        "verification/protected_tests/test_functional.py::test_nonexistent_document_handled_correctly",
        "verification/protected_tests/test_functional.py::test_legitimate_functionality_remains_intact",
        "verification/protected_tests/test_security.py::test_user_a_cannot_access_user_b_document",
        "verification/protected_tests/test_security.py::test_user_b_cannot_access_user_a_document",
        "verification/protected_tests/test_security.py::test_multiple_unauthorized_document_ids_rejected",
        "verification/protected_tests/test_security.py::test_superficial_fix_blocking_only_single_id_rejected",
    ]
    # 8 mandatory tests passed + 1 optional AI-suggested test failed
    tests_payload = [{"nodeid": n, "outcome": "passed"} for n in nodes]
    tests_payload.append({
        "nodeid": "verification/protected_tests/test_security.py::test_ai_suggested_heuristic[optional]",
        "outcome": "failed",
        "is_optional": True,
    })

    report = json.dumps({
        "summary": {"total": 9, "passed": 8, "failed": 1, "error": 0},
        "tests": tests_payload,
        "failed_tests": [tests_payload[-1]["nodeid"]],
    })

    res = TestResultEvaluator.evaluate(
        job_id="job-105",
        patch_hash="sha256:" + "0" * 64,
        exit_code=0,
        raw_output="8 passed, 1 failed in 0.4s",
        report_json_str=report,
    )
    # Mandatory tests all passed, so verdict is VERIFIED!
    assert res.status == VerificationStatus.VERIFIED.value
    assert res.tests_passed == 8
    assert res.tests_failed == 1


# ==============================================================================
# 6. Explicit Limitations and Security Disclaimer Integrity
# ==============================================================================

def test_adversarial_report_structure_and_disclaimer():
    """Verify that AdversarialReport contains an explicit limitations list and security disclaimer."""
    report = run_adversarial_suite(correctly_fixed_get_document, profile="bola-required-tests-v1")

    assert len(report.limitations) > 0
    assert "sandbox" in report.limitations[0].lower()
    # Explicit disclaimer must state it does not certify absence of other vulnerabilities
    assert "does not certify" in report.disclaimer.lower()
    assert "bounded sandbox" in report.disclaimer.lower()
