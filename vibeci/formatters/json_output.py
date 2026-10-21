"""JSON formatter for AI coding agents and automated tooling."""

from __future__ import annotations

import json
from typing import Any

from vibeci.models import VerificationReport


def format_json_report(report: VerificationReport, indent: int = 2) -> str:
    """Format verification report into stable, concise JSON for AI agents."""
    data = report.to_dict()

    # Add quick agent hints if there are failures
    if report.status.value == "failed":
        failed_checks = [c for c in report.checks if c.status.value in ("failed", "error")]
        hint = {
            "action_required": "Inspect the failure_details and file_locations for failed checks, resolve the errors, and rerun verification.",
            "failed_check_names": [c.name for c in failed_checks],
        }
        data["agent_hint"] = hint

    return json.dumps(data, indent=indent)
