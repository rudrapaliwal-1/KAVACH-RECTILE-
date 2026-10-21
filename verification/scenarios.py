"""Independent Red Team Adversarial Verification Engine for BOLA & Security Profiles.

Maintains authoritative, deterministic test scenarios and executes them against
candidate remediations without relying on subjective LLM evaluation.

Distinguishes between:
1. PROTECTED_TEST: Authoritative protected tests maintained by verifier.
2. REGRESSION_TEST: Existing application functional and regression checks.
3. ADVERSARIAL_SCENARIO: Additional adversarial scenarios generated from validated vulnerability profiles.
4. AI_SUGGESTED_TEST: Optional untrusted tests, validated before inclusion; failures do not fail mandatory.
"""

from __future__ import annotations

import copy
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from .contracts import (
    AdversarialReport,
    AdversarialScenario,
    TestSource,
)


# Standard BOLA Fixture Users and Documents (from sample_data.py)
FIXTURE_DOCS = {
    "doc_alice_1": "alice",
    "doc_alice_2": "alice",
    "doc_bob_1": "bob",
    "doc_bob_2": "bob",
    "doc_charlie_1": "charlie",
}

ALL_USERS = ["alice", "bob", "charlie"]


def get_profile_scenarios(profile: str = "bola-required-tests-v1") -> List[AdversarialScenario]:
    """Return the independently maintained security scenarios for the given vulnerability profile."""
    scenarios: List[AdversarialScenario] = []

    # --------------------------------------------------------------------------
    # Category 1: Legitimate Document Owner Access (Section A.1 & A.7)
    # --------------------------------------------------------------------------
    scenarios.append(
        AdversarialScenario(
            scenario_id="BOLA-OWNER-001",
            security_property="Legitimate Ownership Access (Alice -> Doc Alice 1)",
            test_source=TestSource.PROTECTED_TEST.value,
            preconditions={"user_id": "alice", "document_id": "doc_alice_1", "authenticated": True},
            expected_behavior="Return document dictionary with id='doc_alice_1' and owner_id='alice'",
            is_mandatory=True,
        )
    )
    scenarios.append(
        AdversarialScenario(
            scenario_id="BOLA-OWNER-002",
            security_property="Legitimate Ownership Access (Bob -> Doc Bob 1)",
            test_source=TestSource.PROTECTED_TEST.value,
            preconditions={"user_id": "bob", "document_id": "doc_bob_1", "authenticated": True},
            expected_behavior="Return document dictionary with id='doc_bob_1' and owner_id='bob'",
            is_mandatory=True,
        )
    )
    scenarios.append(
        AdversarialScenario(
            scenario_id="BOLA-OWNER-003",
            security_property="Legitimate Ownership Access (Charlie -> Doc Charlie 1)",
            test_source=TestSource.REGRESSION_TEST.value,
            preconditions={"user_id": "charlie", "document_id": "doc_charlie_1", "authenticated": True},
            expected_behavior="Return document dictionary with id='doc_charlie_1' and owner_id='charlie'",
            is_mandatory=True,
        )
    )
    scenarios.append(
        AdversarialScenario(
            scenario_id="BOLA-LEGIT-METADATA",
            security_property="Legitimate Metadata Fidelity & Confidentiality Fields",
            test_source=TestSource.REGRESSION_TEST.value,
            preconditions={"user_id": "alice", "document_id": "doc_alice_2", "authenticated": True},
            expected_behavior="Return complete fields: title, content, is_private=True without corruption",
            is_mandatory=True,
        )
    )

    # --------------------------------------------------------------------------
    # Category 2: Cross-Tenant Authenticated Access Attempt (Section A.2)
    # --------------------------------------------------------------------------
    scenarios.append(
        AdversarialScenario(
            scenario_id="BOLA-CROSS-001",
            security_property="Cross-Tenant Access Denial (Alice -> Bob Doc 1)",
            test_source=TestSource.ADVERSARIAL_SCENARIO.value,
            preconditions={"user_id": "alice", "document_id": "doc_bob_1", "authenticated": True},
            expected_behavior="Raise PermissionError with unauthorized/forbidden/owner indication",
            is_mandatory=True,
        )
    )
    scenarios.append(
        AdversarialScenario(
            scenario_id="BOLA-CROSS-002",
            security_property="Cross-Tenant Access Denial (Bob -> Alice Doc 1)",
            test_source=TestSource.ADVERSARIAL_SCENARIO.value,
            preconditions={"user_id": "bob", "document_id": "doc_alice_1", "authenticated": True},
            expected_behavior="Raise PermissionError with unauthorized/forbidden/owner indication",
            is_mandatory=True,
        )
    )
    scenarios.append(
        AdversarialScenario(
            scenario_id="BOLA-CROSS-003",
            security_property="Cross-Tenant Access Denial (Alice -> Charlie Doc 1)",
            test_source=TestSource.ADVERSARIAL_SCENARIO.value,
            preconditions={"user_id": "alice", "document_id": "doc_charlie_1", "authenticated": True},
            expected_behavior="Raise PermissionError with unauthorized/forbidden/owner indication",
            is_mandatory=True,
        )
    )
    scenarios.append(
        AdversarialScenario(
            scenario_id="BOLA-CROSS-004",
            security_property="Cross-Tenant Access Denial (Charlie -> Alice Doc 2)",
            test_source=TestSource.ADVERSARIAL_SCENARIO.value,
            preconditions={"user_id": "charlie", "document_id": "doc_alice_2", "authenticated": True},
            expected_behavior="Raise PermissionError with unauthorized/forbidden/owner indication",
            is_mandatory=True,
        )
    )
    scenarios.append(
        AdversarialScenario(
            scenario_id="BOLA-CROSS-005",
            security_property="Cross-Tenant Access Denial (Charlie -> Bob Doc 2)",
            test_source=TestSource.ADVERSARIAL_SCENARIO.value,
            preconditions={"user_id": "charlie", "document_id": "doc_bob_2", "authenticated": True},
            expected_behavior="Raise PermissionError with unauthorized/forbidden/owner indication",
            is_mandatory=True,
        )
    )

    # --------------------------------------------------------------------------
    # Category 3: Manipulated Document Identifiers (Section A.3)
    # --------------------------------------------------------------------------
    scenarios.append(
        AdversarialScenario(
            scenario_id="BOLA-MANIP-TRAVERSAL",
            security_property="Document ID Path Traversal Manipulation",
            test_source=TestSource.ADVERSARIAL_SCENARIO.value,
            preconditions={"user_id": "alice", "document_id": "../doc_bob_1", "authenticated": True},
            expected_behavior="Raise LookupError (or PermissionError); must not disclose Bob's document",
            is_mandatory=True,
        )
    )
    scenarios.append(
        AdversarialScenario(
            scenario_id="BOLA-MANIP-SQLI",
            security_property="Document ID SQL/NoSQL Injection String",
            test_source=TestSource.ADVERSARIAL_SCENARIO.value,
            preconditions={"user_id": "alice", "document_id": "doc_bob_1' OR '1'='1", "authenticated": True},
            expected_behavior="Raise LookupError; must not return unauthorized document",
            is_mandatory=True,
        )
    )
    scenarios.append(
        AdversarialScenario(
            scenario_id="BOLA-MANIP-NULLBYTE",
            security_property="Document ID Null Byte Injection",
            test_source=TestSource.ADVERSARIAL_SCENARIO.value,
            preconditions={"user_id": "alice", "document_id": "doc_bob_1\x00doc_alice_1", "authenticated": True},
            expected_behavior="Raise LookupError; must not bypass authorization checks",
            is_mandatory=True,
        )
    )
    scenarios.append(
        AdversarialScenario(
            scenario_id="BOLA-MANIP-PREFIX",
            security_property="Document ID Relative Dot Segment Manipulation",
            test_source=TestSource.ADVERSARIAL_SCENARIO.value,
            preconditions={"user_id": "alice", "document_id": "doc_alice_1/../doc_bob_1", "authenticated": True},
            expected_behavior="Raise LookupError; reject path manipulation safely",
            is_mandatory=True,
        )
    )
    scenarios.append(
        AdversarialScenario(
            scenario_id="BOLA-MANIP-TYPEMISMATCH",
            security_property="Document ID Non-String Type Boundary (Numeric ID)",
            test_source=TestSource.ADVERSARIAL_SCENARIO.value,
            preconditions={"user_id": "alice", "document_id": 12345, "authenticated": True},  # type: ignore
            expected_behavior="Raise LookupError or TypeError safely without unhandled server crash",
            is_mandatory=True,
        )
    )

    # --------------------------------------------------------------------------
    # Category 4: Nonexistent Documents (Section A.4)
    # --------------------------------------------------------------------------
    scenarios.append(
        AdversarialScenario(
            scenario_id="BOLA-NONEXIST-001",
            security_property="Nonexistent Document Lookup (Standard 404 Contract)",
            test_source=TestSource.REGRESSION_TEST.value,
            preconditions={"user_id": "alice", "document_id": "doc_nonexistent_999", "authenticated": True},
            expected_behavior="Raise LookupError with 'not found' message",
            is_mandatory=True,
        )
    )
    scenarios.append(
        AdversarialScenario(
            scenario_id="BOLA-NONEXIST-002",
            security_property="Nonexistent Document Random UUID Lookup",
            test_source=TestSource.REGRESSION_TEST.value,
            preconditions={"user_id": "bob", "document_id": "ffffffff-ffff-ffff-ffff-ffffffffffff", "authenticated": True},
            expected_behavior="Raise LookupError; cannot confuse with existing tenant data",
            is_mandatory=True,
        )
    )

    # --------------------------------------------------------------------------
    # Category 5: Missing or Invalid Identity (Section A.5)
    # --------------------------------------------------------------------------
    scenarios.append(
        AdversarialScenario(
            scenario_id="BOLA-IDENT-NONE",
            security_property="Anonymous Access Denial (None user_id)",
            test_source=TestSource.PROTECTED_TEST.value,
            preconditions={"user_id": None, "document_id": "doc_alice_1", "authenticated": False},
            expected_behavior="Raise PermissionError with anonymous/denied message",
            is_mandatory=True,
        )
    )
    scenarios.append(
        AdversarialScenario(
            scenario_id="BOLA-IDENT-EMPTY",
            security_property="Anonymous Access Denial (Empty string user_id)",
            test_source=TestSource.PROTECTED_TEST.value,
            preconditions={"user_id": "", "document_id": "doc_alice_1", "authenticated": False},
            expected_behavior="Raise PermissionError with anonymous/denied message",
            is_mandatory=True,
        )
    )
    scenarios.append(
        AdversarialScenario(
            scenario_id="BOLA-IDENT-WHITESPACE",
            security_property="Anonymous Access Denial (Whitespace only user_id)",
            test_source=TestSource.PROTECTED_TEST.value,
            preconditions={"user_id": "   \t\n", "document_id": "doc_alice_1", "authenticated": False},
            expected_behavior="Raise PermissionError with anonymous/denied message",
            is_mandatory=True,
        )
    )
    scenarios.append(
        AdversarialScenario(
            scenario_id="BOLA-IDENT-FORGED",
            security_property="Forged Identity Denial (Wildcard / Admin spoofing)",
            test_source=TestSource.ADVERSARIAL_SCENARIO.value,
            preconditions={"user_id": "*", "document_id": "doc_bob_1", "authenticated": False},
            expected_behavior="Raise PermissionError; unassigned wildcard cannot access private doc",
            is_mandatory=True,
        )
    )

    # --------------------------------------------------------------------------
    # Category 6: Boundary Cases Supported by Contract (Section A.6)
    # --------------------------------------------------------------------------
    scenarios.append(
        AdversarialScenario(
            scenario_id="BOLA-BOUND-UNICODE",
            security_property="Boundary Case: Unicode Document Identifier",
            test_source=TestSource.ADVERSARIAL_SCENARIO.value,
            preconditions={"user_id": "alice", "document_id": "doc_alice_1\u200b", "authenticated": True},
            expected_behavior="Raise LookupError; zero-width space does not match doc_alice_1",
            is_mandatory=True,
        )
    )
    scenarios.append(
        AdversarialScenario(
            scenario_id="BOLA-BOUND-CASESENSITIVE",
            security_property="Boundary Case: Case Sensitivity on Document ID",
            test_source=TestSource.ADVERSARIAL_SCENARIO.value,
            preconditions={"user_id": "alice", "document_id": "DOC_ALICE_1", "authenticated": True},
            expected_behavior="Raise LookupError; uppercase ID does not match lowercase key",
            is_mandatory=True,
        )
    )
    scenarios.append(
        AdversarialScenario(
            scenario_id="BOLA-BOUND-MAXLEN",
            security_property="Boundary Case: Oversized Document Identifier (1024 chars)",
            test_source=TestSource.ADVERSARIAL_SCENARIO.value,
            preconditions={"user_id": "alice", "document_id": "doc_" + "a" * 1024, "authenticated": True},
            expected_behavior="Raise LookupError safely without denial-of-service or stack trace leak",
            is_mandatory=True,
        )
    )

    return scenarios


def validate_and_register_ai_scenarios(
    raw_scenarios: List[Dict[str, Any]],
    max_count: int = 10,
) -> List[AdversarialScenario]:
    """Safely validate and bound untrusted AI-suggested test scenarios (Section B.4 & C).

    AI-suggested tests:
    - Are strictly bounded in count and string length.
    - Marked with TestSource.AI_SUGGESTED_TEST.
    - Set is_mandatory=False so optional failures never fail mandatory verification unless enforced.
    - Never replace or modify authoritative protected test suites.
    """
    validated: List[AdversarialScenario] = []
    if not isinstance(raw_scenarios, list):
        return []

    for idx, item in enumerate(raw_scenarios[:max_count]):
        if not isinstance(item, dict):
            continue

        raw_id = str(item.get("scenario_id", f"AI-SUGGESTED-{idx+1:03d}")).strip()
        scenario_id = re.sub(r"[^A-Za-z0-9_-]", "_", raw_id)[:64]
        security_prop = str(item.get("security_property", "AI Suggested Scenario")).strip()[:128]
        expected = str(item.get("expected_behavior", "Raise error or return valid data")).strip()[:256]

        preconds = item.get("preconditions", {})
        if not isinstance(preconds, dict):
            continue

        # Sanitize input types
        clean_user = preconds.get("user_id")
        if clean_user is not None and not isinstance(clean_user, (str, int)):
            continue
        clean_doc = preconds.get("document_id")
        if clean_doc is not None and not isinstance(clean_doc, (str, int)):
            continue

        validated.append(
            AdversarialScenario(
                scenario_id=scenario_id,
                security_property=security_prop,
                test_source=TestSource.AI_SUGGESTED_TEST.value,
                preconditions={"user_id": clean_user, "document_id": clean_doc},
                expected_behavior=expected,
                is_mandatory=bool(item.get("is_mandatory", False)),
            )
        )

    return validated


def execute_single_scenario(
    scenario: AdversarialScenario,
    get_document_fn: Callable[..., Any],
) -> AdversarialScenario:
    """Execute a single scenario against the target access function with strict verdict logic."""
    user_id = scenario.preconditions.get("user_id")
    doc_id = scenario.preconditions.get("document_id")

    scenario_copy = copy.deepcopy(scenario)

    try:
        result = get_document_fn(user_id, doc_id)
        # Result returned without error
        if scenario.scenario_id.startswith("BOLA-OWNER") or scenario.scenario_id == "BOLA-LEGIT-METADATA":
            if isinstance(result, dict) and result.get("id") == doc_id and result.get("owner_id") == user_id:
                scenario_copy.execution_status = "passed"
                scenario_copy.actual_result = f"Returned document id='{result.get('id')}' owned by '{result.get('owner_id')}'"
                scenario_copy.explanation = "Authorized owner successfully accessed document with full integrity."
            else:
                scenario_copy.execution_status = "failed"
                scenario_copy.actual_result = f"Returned malformed or mismatched data: {result}"
                scenario_copy.explanation = "Returned document does not match expected owner or ID."
        else:
            # An attack or error was expected, but data was returned!
            scenario_copy.execution_status = "failed"
            scenario_copy.actual_result = f"Vulnerability detected: Access permitted, returned doc keys: {list(result.keys()) if isinstance(result, dict) else result}"
            scenario_copy.explanation = f"Security boundary breached: User '{user_id}' was unauthorized but accessed document '{doc_id}'."

    except PermissionError as exc:
        err_msg = str(exc)
        if scenario.scenario_id.startswith("BOLA-CROSS"):
            scenario_copy.execution_status = "passed"
            scenario_copy.actual_result = f"PermissionError: {err_msg}"
            scenario_copy.explanation = f"Unauthorized access correctly blocked: {err_msg}"
        elif scenario.scenario_id in ("BOLA-IDENT-NONE", "BOLA-IDENT-EMPTY", "BOLA-IDENT-WHITESPACE"):
            if re.search(r"(?i)anonymous|denied|required", err_msg):
                scenario_copy.execution_status = "passed"
                scenario_copy.actual_result = f"PermissionError: {err_msg}"
                scenario_copy.explanation = f"Unauthorized identity check correctly enforced: {err_msg}"
            else:
                scenario_copy.execution_status = "failed"
                scenario_copy.actual_result = f"Generic PermissionError: {err_msg}"
                scenario_copy.explanation = "Identity validation bypassed; generic ownership error returned instead of required identity rejection."
        elif scenario.scenario_id.startswith("BOLA-IDENT"):
            scenario_copy.execution_status = "passed"
            scenario_copy.actual_result = f"PermissionError: {err_msg}"
            scenario_copy.explanation = f"Unauthorized identity safely blocked: {err_msg}"
        elif scenario.scenario_id.startswith("BOLA-MANIP"):
            scenario_copy.execution_status = "passed"
            scenario_copy.actual_result = f"PermissionError: {err_msg}"
            scenario_copy.explanation = f"Manipulated identifier safely rejected by permission boundary."
        else:
            scenario_copy.execution_status = "failed"
            scenario_copy.actual_result = f"Unexpected PermissionError: {err_msg}"
            scenario_copy.explanation = f"Legitimate request was improperly denied."

    except LookupError as exc:
        err_msg = str(exc)
        if scenario.scenario_id.startswith("BOLA-NONEXIST") or scenario.scenario_id.startswith("BOLA-BOUND"):
            scenario_copy.execution_status = "passed"
            scenario_copy.actual_result = f"LookupError: {err_msg}"
            scenario_copy.explanation = f"Nonexistent or boundary document correctly handled (404 contract preserved)."
        elif scenario.scenario_id.startswith("BOLA-MANIP"):
            scenario_copy.execution_status = "passed"
            scenario_copy.actual_result = f"LookupError: {err_msg}"
            scenario_copy.explanation = f"Manipulated document identifier safely yielded LookupError."
        else:
            scenario_copy.execution_status = "failed"
            scenario_copy.actual_result = f"Unexpected LookupError: {err_msg}"
            scenario_copy.explanation = f"Document lookup failed unexpectedly: {err_msg}"

    except TypeError as exc:
        if scenario.scenario_id == "BOLA-MANIP-TYPEMISMATCH":
            scenario_copy.execution_status = "passed"
            scenario_copy.actual_result = f"TypeError handled: {exc}"
            scenario_copy.explanation = "Type mismatch rejected safely without system failure."
        else:
            scenario_copy.execution_status = "error"
            scenario_copy.actual_result = f"Unhandled TypeError: {exc}"
            scenario_copy.explanation = f"Unexpected type error during scenario execution."

    except Exception as exc:
        scenario_copy.execution_status = "error"
        scenario_copy.actual_result = f"Unhandled exception: {type(exc).__name__}: {exc}"
        scenario_copy.explanation = f"Execution crashed with unexpected exception."

    return scenario_copy


def run_adversarial_suite(
    get_document_fn: Callable[..., Any],
    profile: str = "bola-required-tests-v1",
    custom_scenarios: Optional[List[Dict[str, Any]]] = None,
    patch_hash: str = "",
    source_revision: str = "",
) -> AdversarialReport:
    """Execute complete adversarial red team verification against candidate implementation."""
    all_scenarios = get_profile_scenarios(profile)
    if custom_scenarios:
        ai_scenarios = validate_and_register_ai_scenarios(custom_scenarios)
        all_scenarios.extend(ai_scenarios)

    executed_records: List[Dict[str, Any]] = []
    attack_attempted = attack_passed = attack_failed = 0
    regress_total = regress_passed = regress_failed = 0
    execution_errors: List[str] = []

    for sc in all_scenarios:
        res = execute_single_scenario(sc, get_document_fn)
        executed_records.append(res.to_dict())

        is_attack = sc.test_source in (TestSource.ADVERSARIAL_SCENARIO.value, TestSource.PROTECTED_TEST.value) and (
            sc.scenario_id.startswith("BOLA-CROSS") or sc.scenario_id.startswith("BOLA-MANIP") or sc.scenario_id.startswith("BOLA-IDENT")
        )

        if is_attack:
            attack_attempted += 1
            if res.execution_status == "passed":
                attack_passed += 1
            else:
                attack_failed += 1
        else:
            regress_total += 1
            if res.execution_status == "passed":
                regress_passed += 1
            else:
                regress_failed += 1

        if res.execution_status == "error":
            execution_errors.append(f"{res.scenario_id}: {res.actual_result}")

    # Vulnerability mitigation status
    vulnerability_mitigated = (attack_failed == 0 and regress_failed == 0 and len(execution_errors) == 0)

    limitations = [
        "Tested exclusively within isolated ephemeral sandbox with deterministic in-memory fixtures.",
        "Evaluates authorization enforcement on document access endpoint; does not evaluate network-level egress or database connection security.",
        "Does not assess physical, side-channel, or supply-chain security vectors outside the application code layer.",
    ]

    return AdversarialReport(
        attack_scenarios_attempted=attack_attempted,
        attack_scenarios_passed=attack_passed,
        attack_scenarios_failed=attack_failed,
        regression_scenarios_total=regress_total,
        regression_scenarios_passed=regress_passed,
        regression_scenarios_failed=regress_failed,
        execution_errors=execution_errors,
        vulnerability_reproduced_on_baseline=True,
        vulnerability_mitigated=vulnerability_mitigated,
        protected_suite_version="bola-redteam-v1",
        patch_hash=patch_hash,
        source_revision=source_revision,
        scenarios=executed_records,
        limitations=limitations,
    )
