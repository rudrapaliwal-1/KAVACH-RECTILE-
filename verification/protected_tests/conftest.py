"""Pytest hook to generate structured, tamper-resistant JSON report for the independent evaluator."""

import hashlib
import hmac
import json
import os
import time
from typing import Any, Dict, List

_report_records: List[Dict[str, Any]] = []
_start_times: Dict[str, float] = {}

# Pop ephemeral run token from environment immediately to prevent candidate inspection
_RUN_TOKEN: str | None = os.environ.pop("VERIFICATION_RUN_TOKEN", None)
_EXPECTED_HASH: str = os.environ.get("VERIFICATION_EXPECTED_HASH", "")
_JOB_ID: str = os.environ.get("VERIFICATION_JOB_ID", "")
_RUN_ID: str = os.environ.get("VERIFICATION_RUN_ID", "")


def pytest_runtest_logstart(nodeid: str, location: Any) -> None:
    _start_times[nodeid] = time.time()


def pytest_runtest_logreport(report: Any) -> None:
    if report.when == "call" or (report.when == "setup" and report.failed):
        duration = time.time() - _start_times.get(report.nodeid, time.time())
        record: Dict[str, Any] = {
            "nodeid": report.nodeid,
            "outcome": report.outcome,
            "duration": round(duration, 4),
        }
        if report.failed:
            call_dict: Dict[str, Any] = {}
            if hasattr(report, "longreprtext") and report.longreprtext:
                call_dict["crash"] = {"message": report.longreprtext}
            elif hasattr(report, "longrepr"):
                call_dict["crash"] = {"message": str(report.longrepr)}
            record["call"] = call_dict
        _report_records.append(record)


def pytest_sessionfinish(session: Any, exitstatus: int) -> None:
    report_path = os.environ.get("VERIFICATION_REPORT_PATH", "test_report.json")
    total = len(_report_records)
    passed = sum(1 for r in _report_records if r["outcome"] == "passed")
    failed = sum(1 for r in _report_records if r["outcome"] == "failed")
    error = sum(1 for r in _report_records if r["outcome"] not in ("passed", "failed", "skipped"))
    skipped = sum(1 for r in _report_records if r["outcome"] == "skipped")

    failed_test_names = [r["nodeid"] for r in _report_records if r["outcome"] == "failed"]

    # Execute independent adversarial suite and embed detailed scenario report
    adversarial_report_dict = None
    try:
        from verification.lab.app.access import get_document
        from verification.scenarios import run_adversarial_suite
        adv_report = run_adversarial_suite(
            get_document,
            profile="bola-required-tests-v1",
            patch_hash=_EXPECTED_HASH,
        )
        adversarial_report_dict = adv_report.to_dict()
    except Exception as exc:
        pass

    # Execute controlled mutation testing suite for test quality measurement
    mutation_report_dict = None
    try:
        from verification.mutator import MutationRunner
        mut_report = MutationRunner.run_mutation_suite()
        mutation_report_dict = mut_report.to_dict()
    except Exception as exc:
        pass

    report_payload: Dict[str, Any] = {
        "summary": {
            "total": total,
            "passed": passed,
            "failed": failed,
            "error": error,
            "skipped": skipped,
        },
        "tests": _report_records,
        "failed_tests": failed_test_names,
        "exitstatus": exitstatus,
        "adversarial_report": adversarial_report_dict,
        "mutation_report": mutation_report_dict,
    }

    # Cryptographic attestation binding report contents to the host-issued run token and patch hash
    if _RUN_TOKEN:
        payload_data = f"{total}:{passed}:{failed}:{error}:{exitstatus}:{_EXPECTED_HASH}"
        sig = hmac.new(
            _RUN_TOKEN.encode("utf-8"),
            payload_data.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        report_payload["attestation"] = {
            "signature": sig,
            "patch_hash": _EXPECTED_HASH,
            "job_id": _JOB_ID,
            "run_id": _RUN_ID,
        }

    try:
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report_payload, f, indent=2)
    except Exception as exc:
        print(f"Error writing report to {report_path}: {exc}")
