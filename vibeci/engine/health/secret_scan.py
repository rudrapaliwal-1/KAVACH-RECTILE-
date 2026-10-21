"""Secret leak scanner.

Inspects source code for accidental exposure of private keys, API credentials,
AWS tokens, or hardcoded sensitive connection strings before pushing code to git.
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import List

from vibeci.models import (
    CheckLayer,
    CheckResult,
    CheckStatus,
    CheckType,
    FileLocation,
)

SECRET_PATTERNS = [
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "Hardcoded private cryptographic key"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "Hardcoded AWS Access Key ID"),
    (re.compile(r"\bghp_[0-9a-zA-Z]{36}\b"), "Hardcoded GitHub Personal Access Token"),
    (re.compile(r"\bglpat-[0-9a-zA-Z\-_]{20}\b"), "Hardcoded GitLab Personal Access Token"),
    (re.compile(r"\bsk-proj-[A-Za-z0-9_-]{48,}\b"), "Hardcoded OpenAI Project API Key"),
    (re.compile(r"\bsk-(?:live-)?[0-9a-zA-Z]{24,}\b"), "Hardcoded OpenAI / API secret key"),
    (re.compile(r"\bsk-ant-api03-[A-Za-z0-9_-]{80,}\b"), "Hardcoded Anthropic Claude API Key"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "Hardcoded Google API / Gemini Key"),
    (re.compile(r"\bhf_[A-Za-z0-9]{34,}\b"), "Hardcoded Hugging Face Token"),
    (re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b"), "Hardcoded Stripe Live Secret Key"),
    (re.compile(r"https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]+\/B[0-9A-Z]+\/[0-9a-zA-Z]+"), "Hardcoded Slack Incoming Webhook URL"),
    (re.compile(r"\bxox[baprs]-[0-9a-zA-Z]{10,48}\b"), "Hardcoded Slack Bot / Access Token"),
    (re.compile(r"\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql):\/\/[a-zA-Z0-9_\-\.]+:[a-zA-Z0-9_\-\.\@!#$%^&*()+=~]+@[a-zA-Z0-9_\-\.]+"), "Hardcoded database connection string with password"),
]


class SecretScanner:
    def __init__(self, root_dir: Path):
        self.root_dir = root_dir.resolve()

    def scan(self, target_files: Optional[list[Path]] = None) -> CheckResult:
        start_time = time.perf_counter()

        ignored_dirs = {
            "node_modules", ".git", ".venv", "venv", "dist", "build", ".next",
            "coverage", ".turbo", ".cache", "__pycache__",
        }
        ignored_files = {
            ".env", ".env.local", ".env.production", ".env.development",
            "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "uv.lock",
        }

        leaks: list[tuple[FileLocation, str]] = []
        files_to_scan = target_files if target_files is not None else self.root_dir.rglob("*")

        for path in files_to_scan:
            if any(part in ignored_dirs for part in path.parts):
                continue
            if not path.is_file() or path.name in ignored_files:
                continue
            if "test_engine" in path.name or "test_secret" in path.name:
                continue
            if path.suffix not in {".js", ".jsx", ".ts", ".tsx", ".py", ".json", ".yaml", ".yml", ".toml", ".md", ".html"}:
                continue

            try:
                # Limit scan to text files under 2MB
                if path.stat().st_size > 2 * 1024 * 1024:
                    continue
                content = path.read_text(encoding="utf-8", errors="ignore")
                rel_path = str(path.relative_to(self.root_dir))

                for line_idx, line in enumerate(content.splitlines(), start=1):
                    # Skip common dummy/example lines
                    if "example" in line.lower() or "your_key" in line.lower() or "placeholder" in line.lower():
                        continue

                    for pattern, desc in SECRET_PATTERNS:
                        m = pattern.search(line)
                        if m:
                            leaks.append((
                                FileLocation(file=rel_path, line=line_idx, message=desc),
                                f"{desc} in {rel_path}:{line_idx}",
                            ))
            except Exception:
                continue

        duration_ms = int((time.perf_counter() - start_time) * 1000)

        if leaks:
            status = CheckStatus.FAILED
            summary = f"Detected {len(leaks)} potentially leaked secret(s) in source code."
            failure_details = [desc for _, desc in leaks[:8]]
            file_locations = [loc for loc, _ in leaks[:8]]
        else:
            status = CheckStatus.PASSED
            summary = "No exposed secrets or hardcoded private keys detected."
            failure_details = []
            file_locations = []

        return CheckResult(
            name="security:secrets",
            layer=CheckLayer.SECURITY.value,
            check_type=CheckType.SECURITY.value,
            command="vibeci-internal:secret-scanner",
            status=status,
            exit_code=1 if leaks else 0,
            duration_ms=duration_ms,
            summary=summary,
            failure_details=failure_details,
            file_locations=file_locations,
        )
