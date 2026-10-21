"""IMMUTABLE RED TEAM ADVERSARIAL TEST SUITE (Broken Object-Level Authorization).

Protected from AI edits.
Independently verifies that:
1. Candidate fixes completely eliminate cross-tenant authorization vulnerabilities.
2. Manipulated identifiers (path traversal, SQLi, null bytes, prefix tampering) cannot bypass checks.
3. Boundary cases (unicode, type mismatches, oversized IDs) are safely handled.
4. Deliberately superficial fixes (e.g. blocking only alice -> doc_bob_1) fail verification.
"""

import pytest
from verification.lab.app.access import get_document
from verification.scenarios import run_adversarial_suite, get_profile_scenarios, execute_single_scenario


def test_redteam_adversarial_suite_passes():
    """Verify that all mandatory Red Team adversarial attack scenarios pass against candidate."""
    report = run_adversarial_suite(get_document, profile="bola-required-tests-v1")
    assert report.attack_scenarios_failed == 0, (
        f"Red team detected {report.attack_scenarios_failed} failed attack scenario(s): "
        f"{[s['scenario_id'] for s in report.scenarios if s['execution_status'] != 'passed']}"
    )
    assert report.regression_scenarios_failed == 0, (
        f"Red team detected {report.regression_scenarios_failed} failed regression scenario(s)"
    )
    assert report.vulnerability_mitigated is True, "Candidate patch failed to mitigate BOLA vulnerability"


def test_manipulated_document_ids_strictly_rejected():
    """Verify that path traversal, SQLi, null bytes, and prefix manipulations are rejected."""
    manipulations = [
        "../doc_bob_1",
        "doc_bob_1' OR '1'='1",
        "doc_bob_1\x00doc_alice_1",
        "doc_alice_1/../doc_bob_1",
        "../../etc/passwd",
    ]
    for manipulated_id in manipulations:
        with pytest.raises((LookupError, PermissionError)):
            get_document("alice", manipulated_id)


def test_cross_tenant_matrix_exhaustively_rejected():
    """Exhaustively verify cross-tenant access between all fixture users and documents."""
    cross_tenant_pairs = [
        ("alice", "doc_bob_1"),
        ("alice", "doc_bob_2"),
        ("alice", "doc_charlie_1"),
        ("bob", "doc_alice_1"),
        ("bob", "doc_alice_2"),
        ("bob", "doc_charlie_1"),
        ("charlie", "doc_alice_1"),
        ("charlie", "doc_alice_2"),
        ("charlie", "doc_bob_1"),
        ("charlie", "doc_bob_2"),
    ]
    for user_id, forbidden_doc in cross_tenant_pairs:
        with pytest.raises(PermissionError, match="(?i)unauthorized|forbidden|owner|denied"):
            get_document(user_id, forbidden_doc)


def test_boundary_and_type_tampering_rejected():
    """Verify boundary conditions: unicode zero-width space, case variations, and numeric types."""
    # Unicode variation should not resolve to doc_alice_1
    with pytest.raises(LookupError):
        get_document("alice", "doc_alice_1\u200b")

    # Case sensitivity check
    with pytest.raises(LookupError):
        get_document("alice", "DOC_ALICE_1")

    # Numeric type boundary
    with pytest.raises((LookupError, TypeError)):
        get_document("alice", 999999)  # type: ignore
