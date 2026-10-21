"""Production build verifier.

Tests whether the application can successfully compile, bundle, and produce its
production distribution without missing modules, asset errors, or compilation crashes.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Optional

from vibeci.models import (
    CheckDefinition,
    CheckLayer,
    CheckResult,
    CheckStatus,
    CheckType,
    FileLocation,
)
from vibeci.runner import CheckRunner


class BuildVerifier:
    def __init__(self, root_dir: Path):
        self.root_dir = root_dir.resolve()

    def detect_build_check(self) -> Optional[CheckDefinition]:
        # 1. Check package.json scripts for build
        pkg_json = self.root_dir / "package.json"
        if pkg_json.exists():
            try:
                data = json.loads(pkg_json.read_text(encoding="utf-8"))
                scripts = data.get("scripts", {})
                if "build" in scripts:
                    pm = "npm"
                    if (self.root_dir / "pnpm-lock.yaml").exists() and shutil.which("pnpm"):
                        pm = "pnpm"
                    elif (self.root_dir / "yarn.lock").exists() and shutil.which("yarn"):
                        pm = "yarn"
                    elif (self.root_dir / "bun.lockb").exists() and shutil.which("bun"):
                        pm = "bun"

                    return CheckDefinition(
                        name=f"{pm}:build",
                        command=[pm, "run", "build"],
                        layer=CheckLayer.BUILD,
                        check_type=CheckType.BUILD,
                        cwd=self.root_dir,
                        timeout_seconds=180,
                        description="Verify production build bundles without compilation errors",
                        required=True,
                        discovered_by="build-verifier",
                    )
            except Exception:
                pass

        # 2. Check Python build (if package has pyproject.toml / setup.py)
        if (self.root_dir / "pyproject.toml").exists() and shutil.which("uv"):
            # Check if it has a build backend configured
            content = (self.root_dir / "pyproject.toml").read_text(encoding="utf-8", errors="ignore")
            if "[build-system]" in content:
                return CheckDefinition(
                    name="uv:build",
                    command=["uv", "build"],
                    layer=CheckLayer.BUILD,
                    check_type=CheckType.BUILD,
                    cwd=self.root_dir,
                    timeout_seconds=120,
                    description="Verify Python package build and wheel packaging",
                    required=True,
                    discovered_by="build-verifier",
                )

        return None

    def verify_build(self, runner: CheckRunner) -> Optional[CheckResult]:
        check_def = self.detect_build_check()
        if not check_def:
            return None

        result = runner.run_check(check_def)
        # Refine summary if successful
        if result.status == CheckStatus.PASSED:
            result.summary = "Production build compiled and bundled successfully."
        elif result.status == CheckStatus.FAILED:
            if not result.summary or "exit" in result.summary.lower():
                result.summary = "Production build failed with bundling or compilation errors."

        return result
