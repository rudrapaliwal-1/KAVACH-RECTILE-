"""Environment configuration auditor.

Scans project source files for environment variable references (e.g., process.env.FOO,
os.environ['BAR'], os.getenv('BAZ')) and compares them against .env.example, .env,
and .env.local to catch missing configuration before code reaches remote CI or production.
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Set

from vibeci.models import (
    CheckLayer,
    CheckResult,
    CheckStatus,
    CheckType,
    FileLocation,
)

# Standard framework env vars that are usually provided automatically by the runtime
STANDARD_ENV_VARS = {
    "NODE_ENV", "PORT", "PWD", "HOME", "PATH", "HOST", "HOSTNAME",
    "CI", "DEBUG", "TZ", "PUBLIC_URL", "BROWSER",
    # Vite / modern bundler built-in environment flags (import.meta.env.*)
    "PROD", "DEV", "MODE", "BASE_URL", "SSR",
    # Next.js / Vercel / serverless runtime built-ins
    "NEXT_PHASE", "VERCEL", "VERCEL_ENV",
}

# Regex for process.env.VAR_NAME or process.env["VAR_NAME"]
JS_ENV_PATTERN = re.compile(r"process\.env(?:\.([A-Za-z0-9_]+)|\[['\"]([A-Za-z0-9_]+)['\"]\])")
# Regex for Vite / modern bundler: import.meta.env.VITE_VAR or import.meta.env["VITE_VAR"]
VITE_ENV_PATTERN = re.compile(r"import\.meta\.env(?:\.([A-Za-z0-9_]+)|\[['\"]([A-Za-z0-9_]+)['\"]\])")
# Regex for os.environ["VAR_NAME"], os.environ.get("VAR_NAME"), os.getenv("VAR_NAME")
PY_ENV_PATTERN = re.compile(r"(?:os\.environ(?:\.get)?|os\.getenv)\(['\"]([A-Za-z0-9_]+)['\"]|os\.environ\[['\"]([A-Za-z0-9_]+)['\"]\]")


def parse_env_file(filepath: Path) -> set[str]:
    """Extract variable names declared in a .env file."""
    names: set[str] = set()
    if not filepath.exists() or not filepath.is_file():
        return names

    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                var_name = line.split("=", 1)[0].strip()
                if var_name:
                    names.add(var_name)
    except Exception:
        pass
    return names


class EnvAuditor:
    def __init__(self, root_dir: Path):
        self.root_dir = root_dir.resolve()

    def audit(self, target_files: Optional[list[Path]] = None) -> CheckResult:
        start_time = time.perf_counter()

        # 1. Gather declared environment variables from .env.example, .env.sample, .env.template, .env, .env.local
        example_candidates = [".env.example", ".env.sample", ".env.template", ".env.dist"]
        example_vars: set[str] = set()
        has_env_example = False
        primary_example_name = ".env.example"

        for candidate in example_candidates:
            cand_path = self.root_dir / candidate
            if cand_path.exists():
                has_env_example = True
                primary_example_name = candidate
                example_vars |= parse_env_file(cand_path)

        local_vars = (
            parse_env_file(self.root_dir / ".env")
            | parse_env_file(self.root_dir / ".env.local")
            | parse_env_file(self.root_dir / ".env.development")
        )
        declared_vars = example_vars | local_vars | STANDARD_ENV_VARS

        # 2. Scan source files for env var references
        referenced_vars: dict[str, list[FileLocation]] = {}
        ignored_dirs = {
            "node_modules", ".git", ".venv", "venv", "dist", "build", ".next",
            "coverage", ".turbo", ".cache", "__pycache__",
        }

        extensions = {".js", ".jsx", ".ts", ".tsx", ".py", ".mjs", ".svelte", ".vue", ".astro"}
        files_to_scan = target_files if target_files is not None else self.root_dir.rglob("*")

        for path in files_to_scan:
            if any(part in ignored_dirs for part in path.parts):
                continue
            if not path.is_file() or path.suffix not in extensions:
                continue

            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
                rel_path = str(path.relative_to(self.root_dir))

                lines = content.splitlines()
                for line_idx, line in enumerate(lines, start=1):
                    # Check JS/TS process.env
                    for m in JS_ENV_PATTERN.finditer(line):
                        var_name = m.group(1) or m.group(2)
                        if var_name and not var_name.startswith("_"):
                            referenced_vars.setdefault(var_name, []).append(
                                FileLocation(file=rel_path, line=line_idx, message=f"References process.env.{var_name}")
                            )
                    # Check Vite / modern import.meta.env
                    for m in VITE_ENV_PATTERN.finditer(line):
                        var_name = m.group(1) or m.group(2)
                        if var_name and not var_name.startswith("_"):
                            referenced_vars.setdefault(var_name, []).append(
                                FileLocation(file=rel_path, line=line_idx, message=f"References import.meta.env.{var_name}")
                            )
                    # Check Python os.environ / os.getenv
                    for m in PY_ENV_PATTERN.finditer(line):
                        var_name = m.group(1) or m.group(2)
                        if var_name and not var_name.startswith("_"):
                            referenced_vars.setdefault(var_name, []).append(
                                FileLocation(file=rel_path, line=line_idx, message=f"References os.getenv('{var_name}')")
                            )
            except Exception:
                continue

        # 3. Analyze differences
        missing_from_example: dict[str, list[FileLocation]] = {}
        missing_from_local: dict[str, list[FileLocation]] = {}

        for var_name, locs in referenced_vars.items():
            if var_name in STANDARD_ENV_VARS:
                continue
            if has_env_example and var_name not in example_vars:
                missing_from_example[var_name] = locs
            if not local_vars and not has_env_example:
                continue
            if local_vars and var_name not in local_vars and var_name not in example_vars:
                missing_from_local[var_name] = locs

        duration_ms = int((time.perf_counter() - start_time) * 1000)

        failure_details: list[str] = []
        file_locations: list[FileLocation] = []

        if missing_from_example:
            for var, locs in missing_from_example.items():
                first_loc = locs[0]
                failure_details.append(
                    f"`{var}` is referenced in code ({first_loc.file}:{first_loc.line or ''}) but missing from {primary_example_name}."
                )
                file_locations.extend(locs[:2])

        status = CheckStatus.PASSED
        summary = ""

        if missing_from_example:
            # If an env var is completely missing from example, mark as WARNING so AI/human can fix it
            status = CheckStatus.WARNING
            summary = f"{len(missing_from_example)} referenced environment variable(s) missing from {primary_example_name}."
        elif not has_env_example and not local_vars and not referenced_vars:
            summary = "No environment variables referenced."
        else:
            summary = f"All {len(referenced_vars)} referenced environment variable(s) properly documented in .env.example."

        return CheckResult(
            name="env:preflight",
            layer=CheckLayer.ENV_AUDIT.value,
            check_type=CheckType.ENV.value,
            command="vibeci-internal:env-audit",
            status=status,
            exit_code=0 if status == CheckStatus.PASSED else 1,
            duration_ms=duration_ms,
            summary=summary,
            failure_details=failure_details[:10],
            file_locations=file_locations[:10],
        )
