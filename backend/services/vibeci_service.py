"""VibeCI integration service adapter for KAVACH-X.

Provides secure, repository-aware preflight and multi-layer verification for
onboarded projects and candidate patches. Enforces path containment, execution
timeouts, output-size bounds, and secret redaction.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from vibeci.config import VibeConfig
from vibeci.detectors import discover_checks
from vibeci.detectors.vercel import audit_vercel_functions
from vibeci.engine.build.build_verifier import BuildVerifier
from vibeci.engine.coordinator import VerificationEngine
from vibeci.engine.diff.analyzer import GitChangeAnalyzer
from vibeci.engine.health.env_audit import EnvAuditor
from vibeci.engine.health.secret_scan import SecretScanner
from vibeci.engine.runtime.smoke_tester import RuntimeSmokeTester
from vibeci.models import (
    CheckDefinition,
    CheckLayer,
    CheckResult,
    CheckStatus,
    CheckType,
    OverallStatus,
    UnverifiedCapability,
    VerificationReport,
)
from vibeci.rules import get_rule_status, install_rules
from vibeci.runner import CheckRunner

# Maximum allowed stdout/stderr in memory and persisted reports (64 KB)
MAX_OUTPUT_BYTES = 64 * 1024
DEFAULT_TIMEOUT_SECONDS = 30
MAX_TIMEOUT_SECONDS = 120

# Patterns for redacting credentials from diagnostics and logs
REDACT_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[0-9a-zA-Z]{36}"),
    re.compile(r"glpat-[0-9a-zA-Z\-_]{20}"),
    re.compile(r"sk-proj-[A-Za-z0-9_-]{32,}"),
    re.compile(r"sk-(?:live-)?[0-9a-zA-Z]{24,}"),
    re.compile(r"sk-ant-api03-[A-Za-z0-9_-]{40,}"),
    re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    re.compile(r"hf_[A-Za-z0-9]{34,}"),
    re.compile(r"(?:sk|rk)_live_[0-9a-zA-Z]{24,}"),
    re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}"),
    re.compile(r":\/\/[a-zA-Z0-9_\-\.]+:[^@\s]+@[a-zA-Z0-9_\-\.]+"),
]


def redact_secrets(text: str) -> str:
    """Mask credentials and sensitive strings from logs and diagnostics."""
    if not text:
        return ""
    sanitized = text
    for pattern in REDACT_PATTERNS:
        sanitized = pattern.sub("[REDACTED_CREDENTIAL]", sanitized)
    return sanitized


def validate_contained_path(root: Path, target: Path | str) -> Path:
    """Ensure target path is strictly contained within authorized root directory."""
    root_resolved = root.resolve()
    target_path = Path(target)
    if not target_path.is_absolute():
        target_resolved = (root_resolved / target_path).resolve()
    else:
        target_resolved = target_path.resolve()

    if not target_resolved.is_relative_to(root_resolved):
        raise ValueError(f"Path traversal detected: {target} is outside {root}")
    return target_resolved


@dataclass
class VibeCIOptions:
    run_static: bool = True
    run_build: bool = False
    run_tests: bool = True
    run_smoke: bool = False
    changed_only: bool = False
    compare_ref: Optional[str] = None
    fail_fast: bool = False
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS


class VibeCIService:
    """Security-hardened adapter around vibeCI's multi-layered verification engine."""

    def __init__(self, settings: Any = None):
        self.settings = settings
        self.version = "0.3.0"

    def get_status(self) -> dict[str, Any]:
        """Return integration availability, detected host tools, and supported capabilities."""
        tools = {
            "pytest": bool(shutil.which("pytest")),
            "npm": bool(shutil.which("npm")),
            "pnpm": bool(shutil.which("pnpm")),
            "yarn": bool(shutil.which("yarn")),
            "bun": bool(shutil.which("bun")),
            "uv": bool(shutil.which("uv")),
            "ruff": bool(shutil.which("ruff")),
            "mypy": bool(shutil.which("mypy")),
            "tsc": bool(shutil.which("tsc")),
            "git": bool(shutil.which("git")),
        }
        return {
            "service": "vibeci",
            "version": self.version,
            "available": True,
            "available_layers": [
                "static_health",
                "env_audit",
                "security",
                "build",
                "behavior",
                "runtime_smoke",
                "honest_boundaries",
            ],
            "detected_tools": tools,
            "default_timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
            "max_timeout_seconds": MAX_TIMEOUT_SECONDS,
        }

    def run_preflight_audit(
        self,
        project_root: Path,
        target_files: Optional[list[Path]] = None,
    ) -> VerificationReport:
        """Fast, sub-second preflight audit: secret scanning, environment audit,
        serverless limits, and honest boundary identification. Completely non-executing.
        """
        root = project_root.resolve()
        start_time = time.perf_counter()

        ecosystem, _ = discover_checks(root)
        report = VerificationReport(
            project_name=root.name,
            project_type=ecosystem,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )

        results: list[CheckResult] = []

        # 1. Environment preflight
        env_res = EnvAuditor(root).audit(target_files=target_files)
        results.append(self._sanitize_result(env_res))

        # 2. Secret leak audit
        sec_res = SecretScanner(root).scan(target_files=target_files)
        results.append(self._sanitize_result(sec_res))

        # 3. Platform limits (Vercel)
        vercel_res = audit_vercel_functions(root)
        if vercel_res:
            results.append(self._sanitize_result(vercel_res))

        # 4. Honest unverified capabilities
        engine = VerificationEngine(root)
        report.checks = results
        report.unverified = engine.identify_unverified_capabilities(results)
        report.total_duration_ms = int((time.perf_counter() - start_time) * 1000)
        report.compute_status()
        return report

    def run_verification(
        self,
        project_root: Path,
        options: Optional[VibeCIOptions] = None,
    ) -> VerificationReport:
        """Run full multi-layer verification with security constraints."""
        root = project_root.resolve()
        opts = options or VibeCIOptions()
        timeout = min(max(1, opts.timeout_seconds), MAX_TIMEOUT_SECONDS)

        engine = VerificationEngine(root)
        raw_report = engine.verify(
            run_static=opts.run_static,
            run_build=opts.run_build,
            run_tests=opts.run_tests,
            run_smoke=opts.run_smoke,
            changed_only=opts.changed_only,
            compare_ref=opts.compare_ref,
            fail_fast=opts.fail_fast,
            timeout_seconds=timeout,
        )

        # Sanitize all outputs and failure details
        sanitized_checks = [self._sanitize_result(c) for c in raw_report.checks]
        raw_report.checks = sanitized_checks
        return raw_report

    def get_agent_rules(self, project_root: Path) -> dict[str, Any]:
        """Check status of installed AI coding agent rules."""
        root = project_root.resolve()
        return get_rule_status(root)

    def install_agent_rules(self, project_root: Path, agent: str = "all") -> dict[str, Any]:
        """Install or update AI coding assistant instructions for vibeCI."""
        root = project_root.resolve()
        installed = install_rules(root, agent=agent)
        return {
            "status": "installed",
            "agent": agent,
            "installed_files": [str(p) for p in installed],
        }

    def _sanitize_result(self, result: CheckResult) -> CheckResult:
        """Redact secrets and truncate large outputs to prevent data leakage and memory exhaustion."""
        # Redact summary and failure details
        result.summary = redact_secrets(result.summary)
        result.failure_details = [redact_secrets(d) for d in result.failure_details]

        for loc in result.file_locations:
            if loc.message:
                loc.message = redact_secrets(loc.message)

        # Truncate and redact stdout/stderr
        if len(result.stdout) > MAX_OUTPUT_BYTES:
            result.stdout = result.stdout[:MAX_OUTPUT_BYTES] + "\n... [TRUNCATED_DUE_TO_SIZE]"
        result.stdout = redact_secrets(result.stdout)

        if len(result.stderr) > MAX_OUTPUT_BYTES:
            result.stderr = result.stderr[:MAX_OUTPUT_BYTES] + "\n... [TRUNCATED_DUE_TO_SIZE]"
        result.stderr = redact_secrets(result.stderr)

        return result
