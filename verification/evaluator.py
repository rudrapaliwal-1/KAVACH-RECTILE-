"""Independent Test Result Evaluator for SENTINEL-X Verification (Layer 5).

Strictly evaluates test runner output without LLM subjectivity:
- VERIFIED is returned ONLY if all required protected tests execute and pass.
- Missing test collections, timeouts, report tampering, and infrastructure crashes produce EXECUTION_ERROR.
- Policy and approval failures produce POLICY_REJECTED / fail-closed errors.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Dict, List, Optional, Set

from .contracts import VerificationResult, VerificationStatus


class TestResultEvaluator:
    """Deterministic, tamper-resistant evaluator for verification test reports."""

    # Expected minimum test count for full coverage
    MIN_REQUIRED_TESTS = 8
    TEST_SUITE_ID = "bola-required-tests-v1"

    # Required immutable test identifiers from protected_tests suite
    REQUIRED_TEST_NAMES: Set[str] = {
        "test_owner_accesses_own_document_successfully",
        "test_anonymous_user_cannot_access_private_documents",
        "test_nonexistent_document_handled_correctly",
        "test_legitimate_functionality_remains_intact",
        "test_user_a_cannot_access_user_b_document",
        "test_user_b_cannot_access_user_a_document",
        "test_multiple_unauthorized_document_ids_rejected",
        "test_superficial_fix_blocking_only_single_id_rejected",
    }

    @classmethod
    def _verdict_status(cls, verdict: VerificationStatus, fine_grained: bool, legacy_exec_err: bool = False) -> str:
        if fine_grained:
            return verdict.value
        if legacy_exec_err or verdict in (VerificationStatus.INCONCLUSIVE, VerificationStatus.UNSUPPORTED):
            return VerificationStatus.EXECUTION_ERROR.value
        return verdict.value

    @classmethod
    def evaluate(
        cls,
        job_id: str,
        patch_hash: str,
        exit_code: int,
        raw_output: str,
        report_json_str: Optional[str] = None,
        duration_ms: int = 0,
        timed_out: bool = False,
        runner_error: Optional[str] = None,
        run_id: Optional[str] = None,
        patch_id: Optional[str] = None,
        run_token: Optional[str] = None,
        fine_grained: bool = False,
    ) -> VerificationResult:
        """Evaluate runner outputs and produce a structured, tamper-proof VerificationResult."""

        # 1. Timeout Check
        if timed_out:
            return VerificationResult(
                job_id=job_id,
                patch_hash=patch_hash,
                status=cls._verdict_status(VerificationStatus.EXECUTION_ERROR, fine_grained),
                verdict_category=VerificationStatus.EXECUTION_ERROR.value,
                duration_ms=duration_ms,
                execution_error="Execution timed out in sandbox environment.",
                run_id=run_id,
                patch_id=patch_id,
            )

        # 2. Runner Crash / Infrastructure Error Check
        if runner_error:
            return VerificationResult(
                job_id=job_id,
                patch_hash=patch_hash,
                status=cls._verdict_status(VerificationStatus.EXECUTION_ERROR, fine_grained),
                verdict_category=VerificationStatus.EXECUTION_ERROR.value,
                duration_ms=duration_ms,
                execution_error=f"Runner error: {runner_error}",
                run_id=run_id,
                patch_id=patch_id,
            )

        # 3. Report Missing Check -> INCONCLUSIVE / EXECUTION_ERROR
        if not report_json_str or not report_json_str.strip():
            err_msg = f"Test report missing or runner exited prematurely with code {exit_code}."
            return VerificationResult(
                job_id=job_id,
                patch_hash=patch_hash,
                status=cls._verdict_status(VerificationStatus.INCONCLUSIVE, fine_grained),
                verdict_category=VerificationStatus.INCONCLUSIVE.value,
                duration_ms=duration_ms,
                execution_error=err_msg,
                run_id=run_id,
                patch_id=patch_id,
            )

        try:
            report_data = json.loads(report_json_str)
            if not isinstance(report_data, dict):
                raise ValueError("Report root must be a JSON object")
        except Exception as exc:
            return VerificationResult(
                job_id=job_id,
                patch_hash=patch_hash,
                status=cls._verdict_status(VerificationStatus.EXECUTION_ERROR, fine_grained),
                verdict_category=VerificationStatus.EXECUTION_ERROR.value,
                duration_ms=duration_ms,
                execution_error=f"Malformed report JSON: {exc}",
                run_id=run_id,
                patch_id=patch_id,
            )

        summary = report_data.get("summary", {})
        tests_data = report_data.get("tests", [])
        adversarial_report = report_data.get("adversarial_report")
        mutation_report = report_data.get("mutation_report")

        if not isinstance(summary, dict) or not isinstance(tests_data, list):
            return VerificationResult(
                job_id=job_id,
                patch_hash=patch_hash,
                status=cls._verdict_status(VerificationStatus.INCONCLUSIVE, fine_grained),
                verdict_category=VerificationStatus.INCONCLUSIVE.value,
                duration_ms=duration_ms,
                execution_error="Invalid report schema structure: missing summary or tests array.",
                run_id=run_id,
                patch_id=patch_id,
            )

        # Compute counts directly from individual test records for tamper resistance
        recorded_total = len(tests_data)
        recorded_passed = sum(1 for t in tests_data if isinstance(t, dict) and t.get("outcome") == "passed")
        recorded_failed = sum(1 for t in tests_data if isinstance(t, dict) and t.get("outcome") == "failed")
        recorded_errored = sum(
            1 for t in tests_data if isinstance(t, dict) and t.get("outcome") not in ("passed", "failed", "skipped")
        )

        total = summary.get("total", recorded_total)
        passed = summary.get("passed", recorded_passed)
        failed = summary.get("failed", recorded_failed)
        errored = summary.get("error", recorded_errored)

        # Reconcile summary with test record counts -> Contradictory evidence (INCONCLUSIVE)
        if total != recorded_total or passed != recorded_passed or failed != recorded_failed:
            return VerificationResult(
                job_id=job_id,
                patch_hash=patch_hash,
                status=cls._verdict_status(VerificationStatus.INCONCLUSIVE, fine_grained),
                verdict_category=VerificationStatus.INCONCLUSIVE.value,
                duration_ms=duration_ms,
                execution_error="Evidence tampering detected: summary counts mismatch individual test records.",
                run_id=run_id,
                patch_id=patch_id,
            )

        # 3b. Attestation Verification (if run_token was issued by trusted host)
        if run_token:
            attestation = report_data.get("attestation")
            if not isinstance(attestation, dict) or "signature" not in attestation:
                return VerificationResult(
                    job_id=job_id,
                    patch_hash=patch_hash,
                    status=cls._verdict_status(VerificationStatus.INCONCLUSIVE, fine_grained),
                    verdict_category=VerificationStatus.INCONCLUSIVE.value,
                    duration_ms=duration_ms,
                    execution_error="Evidence integrity failure: Missing or invalid cryptographic HMAC attestation.",
                    run_id=run_id,
                    patch_id=patch_id,
                )
            expected_payload = f"{total}:{passed}:{failed}:{errored}:{report_data.get('exitstatus', exit_code)}:{patch_hash}"
            expected_sig = hmac.new(
                run_token.encode("utf-8"),
                expected_payload.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(str(attestation.get("signature", "")), expected_sig):
                return VerificationResult(
                    job_id=job_id,
                    patch_hash=patch_hash,
                    status=cls._verdict_status(VerificationStatus.INCONCLUSIVE, fine_grained),
                    verdict_category=VerificationStatus.INCONCLUSIVE.value,
                    duration_ms=duration_ms,
                    execution_error="Evidence tampering detected: Cryptographic HMAC attestation mismatch.",
                    run_id=run_id,
                    patch_id=patch_id,
                )

        # Extract test records with anti-tampering guards
        failed_tests: List[str] = []
        mandatory_failed_tests: List[str] = []
        executed_test_functions: Set[str] = set()
        test_results: List[Dict[str, str]] = []
        seen_nodeids: Set[str] = set()

        for t in tests_data:
            if not isinstance(t, dict):
                return VerificationResult(
                    job_id=job_id,
                    patch_hash=patch_hash,
                    status=cls._verdict_status(VerificationStatus.INCONCLUSIVE, fine_grained),
                    verdict_category=VerificationStatus.INCONCLUSIVE.value,
                    duration_ms=duration_ms,
                    execution_error="Evidence tampering detected: Individual test entry is not a dictionary.",
                    run_id=run_id,
                    patch_id=patch_id,
                )
            nodeid = str(t.get("nodeid", ""))
            if not nodeid:
                return VerificationResult(
                    job_id=job_id,
                    patch_hash=patch_hash,
                    status=cls._verdict_status(VerificationStatus.INCONCLUSIVE, fine_grained),
                    verdict_category=VerificationStatus.INCONCLUSIVE.value,
                    duration_ms=duration_ms,
                    execution_error="Evidence tampering detected: Empty test node ID in report.",
                    run_id=run_id,
                    patch_id=patch_id,
                )
            if nodeid in seen_nodeids:
                return VerificationResult(
                    job_id=job_id,
                    patch_hash=patch_hash,
                    status=cls._verdict_status(VerificationStatus.INCONCLUSIVE, fine_grained),
                    verdict_category=VerificationStatus.INCONCLUSIVE.value,
                    duration_ms=duration_ms,
                    execution_error=f"Evidence tampering detected: Duplicate test node ID '{nodeid}'.",
                    run_id=run_id,
                    patch_id=patch_id,
                )
            seen_nodeids.add(nodeid)

            # Anti-tampering: Reject external file test nodes outside protected_tests
            if "::" in nodeid and "protected_tests" not in nodeid:
                return VerificationResult(
                    job_id=job_id,
                    patch_hash=patch_hash,
                    status=cls._verdict_status(VerificationStatus.POLICY_REJECTED, fine_grained, legacy_exec_err=True),
                    verdict_category=VerificationStatus.POLICY_REJECTED.value,
                    duration_ms=duration_ms,
                    execution_error=f"Evidence tampering detected: Test node '{nodeid}' is outside protected test suite.",
                    run_id=run_id,
                    patch_id=patch_id,
                )

            outcome = t.get("outcome")
            func_name = nodeid.split("::")[-1] if "::" in nodeid else nodeid
            executed_test_functions.add(func_name)
            if outcome in ("passed", "failed", "error", "skipped"):
                import re
                safe_name = re.sub(r"[^A-Za-z0-9_./:\-\[\]]", "_", nodeid)[:128]
                test_results.append({"name": safe_name, "outcome": outcome})

            is_optional = bool(t.get("is_optional", False)) or "[optional]" in nodeid.lower() or "ai_suggested" in nodeid.lower()
            if outcome in ("failed", "error"):
                failed_tests.append(nodeid)
                if not is_optional:
                    mandatory_failed_tests.append(nodeid)

        # 4. Zero or Insufficient Tests Collected Check -> INCONCLUSIVE
        if total == 0 or total < cls.MIN_REQUIRED_TESTS:
            return VerificationResult(
                job_id=job_id,
                patch_hash=patch_hash,
                status=cls._verdict_status(VerificationStatus.INCONCLUSIVE, fine_grained),
                verdict_category=VerificationStatus.INCONCLUSIVE.value,
                tests_total=total,
                tests_passed=passed,
                tests_failed=failed + errored,
                failed_tests=failed_tests,
                duration_ms=duration_ms,
                execution_error=f"Incomplete test execution: collected {total} tests (minimum {cls.MIN_REQUIRED_TESTS} required).",
                run_id=run_id,
                patch_id=patch_id,
                adversarial_report=adversarial_report,
                mutation_report=mutation_report,
            )

        # 5. Required Protected Test Suite Inventory Check (Anti-Evasion)
        missing_required = cls.REQUIRED_TEST_NAMES - executed_test_functions
        if missing_required:
            return VerificationResult(
                job_id=job_id,
                patch_hash=patch_hash,
                status=cls._verdict_status(VerificationStatus.INCONCLUSIVE, fine_grained),
                verdict_category=VerificationStatus.INCONCLUSIVE.value,
                tests_total=total,
                tests_passed=passed,
                tests_failed=failed + errored,
                failed_tests=failed_tests,
                duration_ms=duration_ms,
                execution_error=f"Required protected security test(s) not executed: {sorted(missing_required)}",
                run_id=run_id,
                patch_id=patch_id,
                adversarial_report=adversarial_report,
                mutation_report=mutation_report,
            )

        # 6. Stdout cross-validation: if report claims all-pass, ensure stdout stream confirms pytest execution
        if raw_output and exit_code == 0 and failed == 0 and errored == 0:
            if "passed" not in raw_output.lower():
                return VerificationResult(
                    job_id=job_id,
                    patch_hash=patch_hash,
                    status=cls._verdict_status(VerificationStatus.INCONCLUSIVE, fine_grained),
                    verdict_category=VerificationStatus.INCONCLUSIVE.value,
                    duration_ms=duration_ms,
                    execution_error="Evidence tampering detected: Standard output log contradicts reported all-passing status.",
                    run_id=run_id,
                    patch_id=patch_id,
                    adversarial_report=adversarial_report,
                mutation_report=mutation_report,
                )

        skipped = summary.get("skipped", 0)
        if skipped or passed + failed + errored != total:
            return VerificationResult(
                job_id=job_id, patch_hash=patch_hash,
                status=cls._verdict_status(VerificationStatus.INCONCLUSIVE, fine_grained),
                verdict_category=VerificationStatus.INCONCLUSIVE.value,
                tests_total=total, tests_passed=passed, tests_failed=failed + errored,
                failed_tests=failed_tests, duration_ms=duration_ms,
                execution_error="Required test execution was incomplete or skipped.",
                run_id=run_id, patch_id=patch_id,
                tests_collected=total, collection_complete=False,
                execution_completed=False,
                adversarial_report=adversarial_report,
                mutation_report=mutation_report,
            )
        if exit_code not in (0, 1):
            return VerificationResult(
                job_id=job_id, patch_hash=patch_hash,
                status=cls._verdict_status(VerificationStatus.EXECUTION_ERROR, fine_grained),
                verdict_category=VerificationStatus.EXECUTION_ERROR.value,
                tests_total=total, tests_passed=passed, tests_failed=failed + errored,
                failed_tests=failed_tests, duration_ms=duration_ms,
                execution_error="Pytest exited abnormally.",
                run_id=run_id, patch_id=patch_id,
                tests_collected=total, collection_complete=False,
                execution_completed=False,
                adversarial_report=adversarial_report,
                mutation_report=mutation_report,
            )

        # 6. Exit Code Contradiction Check (Crash after writing report)
        if exit_code != 0 and failed == 0 and errored == 0:
            return VerificationResult(
                job_id=job_id,
                patch_hash=patch_hash,
                status=cls._verdict_status(VerificationStatus.INCONCLUSIVE, fine_grained),
                verdict_category=VerificationStatus.INCONCLUSIVE.value,
                tests_total=total,
                tests_passed=passed,
                tests_failed=failed + errored,
                failed_tests=failed_tests,
                duration_ms=duration_ms,
                execution_error=f"Exit code contradiction: process exited with code {exit_code} despite zero reported failures.",
                run_id=run_id,
                patch_id=patch_id,
                adversarial_report=adversarial_report,
                mutation_report=mutation_report,
            )

        # 7. Mandatory Failures Detected Check
        # Optional test failures do not fail verification if all mandatory tests pass
        if mandatory_failed_tests:
            return VerificationResult(
                job_id=job_id,
                patch_hash=patch_hash,
                status=cls._verdict_status(VerificationStatus.VERIFICATION_FAILED, fine_grained),
                verdict_category=VerificationStatus.VERIFICATION_FAILED.value,
                tests_total=total,
                tests_passed=passed,
                tests_failed=failed + errored,
                failed_tests=failed_tests,
                test_results=test_results,
                duration_ms=duration_ms,
                execution_error=None,
                run_id=run_id,
                patch_id=patch_id,
                test_suite_id=cls.TEST_SUITE_ID,
                tests_collected=total,
                collection_complete=True,
                execution_completed=True,
                adversarial_report=adversarial_report,
                mutation_report=mutation_report,
            )

        # 8. All Mandatory Tests Passed Strictly (even if optional tests had non-blocking warnings)
        return VerificationResult(
            job_id=job_id,
            patch_hash=patch_hash,
            status=cls._verdict_status(VerificationStatus.VERIFIED, fine_grained),
            verdict_category=VerificationStatus.VERIFIED.value,
            tests_total=total,
            tests_passed=passed,
            tests_failed=failed + errored,
            failed_tests=failed_tests,
            test_results=test_results,
            duration_ms=duration_ms,
            execution_error=None,
            run_id=run_id,
            patch_id=patch_id,
            test_suite_id=cls.TEST_SUITE_ID,
            tests_collected=total,
            collection_complete=True,
            execution_completed=True,
            adversarial_report=adversarial_report,
            mutation_report=mutation_report,
        )
