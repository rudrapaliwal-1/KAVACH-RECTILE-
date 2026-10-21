"""Data models for VibeCI multi-layered software verification engine."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, List, Optional


class CheckStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    NOT_CHECKED = "not_checked"
    SKIPPED = "skipped"
    TIMED_OUT = "timed_out"
    ERROR = "error"


class OverallStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    WARNINGS = "warnings"
    INCOMPLETE = "incomplete"


class CheckLayer(str, Enum):
    STATIC_HEALTH = "static_health"
    ENV_AUDIT = "env_audit"
    SECURITY = "security"
    BUILD = "build"
    BEHAVIOR = "behavior"
    RUNTIME_SMOKE = "runtime_smoke"
    CUSTOM = "custom"


class CheckType(str, Enum):
    TEST = "test"
    LINT = "lint"
    TYPECHECK = "typecheck"
    BUILD = "build"
    ENV = "env"
    SECURITY = "security"
    IMPORT = "import"
    SMOKE = "smoke"
    CUSTOM = "custom"


@dataclass
class FileLocation:
    file: str
    line: Optional[int] = None
    column: Optional[int] = None
    message: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class UnverifiedCapability:
    name: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "reason": self.reason}


@dataclass
class CheckDefinition:
    name: str
    command: list[str] = field(default_factory=list)
    layer: CheckLayer = CheckLayer.CUSTOM
    check_type: CheckType = CheckType.CUSTOM
    cwd: Optional[Path] = None
    timeout_seconds: Optional[int] = None
    description: str = ""
    required: bool = True
    discovered_by: str = "manual"

    @property
    def display_command(self) -> str:
        return " ".join(self.command) if self.command else "internal"


@dataclass
class CheckResult:
    name: str
    layer: str
    check_type: str
    command: str
    status: CheckStatus
    exit_code: Optional[int] = None
    duration_ms: int = 0
    stdout: str = ""
    stderr: str = ""
    summary: str = ""
    failure_details: list[str] = field(default_factory=list)
    file_locations: list[FileLocation] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "layer": self.layer,
            "type": self.check_type,
            "command": self.command,
            "status": self.status.value,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "summary": self.summary,
            "failure_details": self.failure_details,
            "file_locations": [loc.to_dict() for loc in self.file_locations],
            "stdout": self.stdout,
            "stderr": self.stderr,
        }


@dataclass
class VerificationReport:
    version: str = "0.3.0"
    status: OverallStatus = OverallStatus.PASSED
    project_name: str = ""
    project_type: str = "unknown"
    timestamp: str = ""
    total_duration_ms: int = 0
    checks: list[CheckResult] = field(default_factory=list)
    unverified: list[UnverifiedCapability] = field(default_factory=list)
    incomplete_reason: Optional[str] = None

    @property
    def summary(self) -> dict[str, int]:
        total = len(self.checks)
        passed = sum(1 for c in self.checks if c.status == CheckStatus.PASSED)
        failed = sum(1 for c in self.checks if c.status in (CheckStatus.FAILED, CheckStatus.ERROR))
        warnings = sum(1 for c in self.checks if c.status == CheckStatus.WARNING)
        timed_out = sum(1 for c in self.checks if c.status == CheckStatus.TIMED_OUT)
        not_checked = len(self.unverified) + sum(1 for c in self.checks if c.status in (CheckStatus.NOT_CHECKED, CheckStatus.SKIPPED))
        return {
            "total": total,
            "passed": passed,
            "failed": failed,
            "warnings": warnings,
            "timed_out": timed_out,
            "not_checked": not_checked,
        }

    def compute_status(self) -> OverallStatus:
        if any(c.status in (CheckStatus.FAILED, CheckStatus.ERROR) for c in self.checks):
            self.status = OverallStatus.FAILED
        elif any(c.status == CheckStatus.TIMED_OUT for c in self.checks):
            self.status = OverallStatus.INCOMPLETE
        elif any(c.status == CheckStatus.WARNING for c in self.checks):
            self.status = OverallStatus.WARNINGS
        elif not self.checks and not self.unverified:
            self.status = OverallStatus.INCOMPLETE
        else:
            self.status = OverallStatus.PASSED
        return self.status

    def to_dict(self) -> dict[str, Any]:
        return {
            "vibeci_version": self.version,
            "status": self.status.value,
            "project_name": self.project_name,
            "project_type": self.project_type,
            "timestamp": self.timestamp,
            "total_duration_ms": self.total_duration_ms,
            "summary": self.summary,
            "incomplete_reason": self.incomplete_reason,
            "checks": [c.to_dict() for c in self.checks],
            "unverified_capabilities": [u.to_dict() for u in self.unverified],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
