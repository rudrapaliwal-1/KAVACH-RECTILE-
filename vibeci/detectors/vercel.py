"""Vercel Platform Pre-Flight Check.

Audits Vercel projects for serverless function limits before pushing code,
saving wasted CI/CD runs and surprise platform build failures.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import List, Optional, Set

from vibeci.models import (
    CheckDefinition,
    CheckLayer,
    CheckResult,
    CheckStatus,
    CheckType,
    FileLocation,
)

# Supported extensions in api/ directory
API_EXTENSIONS: Set[str] = {
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".py",
    ".go",
    ".rs",
    ".mjs",
    ".cjs",
}

# Supported extensions in pages/api/ directory
PAGES_API_EXTENSIONS: Set[str] = {
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".mjs",
    ".cjs",
}

# Allowed filenames in app/**/ directory
APP_ROUTE_FILENAMES: Set[str] = {
    "route.js",
    "route.ts",
    "route.jsx",
    "route.tsx",
    "route.mjs",
    "route.cjs",
}

VERCEL_HOBBY_FUNCTION_LIMIT = 12


def is_vercel_project(project_dir: Path | str) -> bool:
    """Return True if project_dir is recognized as a Vercel project.

    Detected via:
    - vercel.json
    - .vercel/ directory
    - api/ directory
    """
    root = Path(project_dir).resolve()
    if (root / "vercel.json").is_file():
        return True
    if (root / ".vercel").is_dir():
        return True
    if (root / "api").is_dir():
        return True
    return False


def is_ignored_file_or_dir(rel_path: Path) -> bool:
    """Check if any segment in rel_path starts with '_' (e.g. _lib/, _utils.ts)."""
    return any(part.startswith("_") for part in rel_path.parts)


def is_test_or_type_file(path: Path) -> bool:
    """Skip test, spec, or typescript declaration files."""
    name_lower = path.name.lower()
    if ".test." in name_lower or ".spec." in name_lower:
        return True
    if name_lower.endswith(".d.ts"):
        return True
    return False


def count_serverless_functions(project_dir: Path | str) -> list[Path]:
    """Discover and return all serverless endpoint files in the project.

    Searches:
    1. api/**/*.{js,ts,py,go,rs} (skipping _* and .test./.spec.)
    2. pages/api/**/*.{js,ts} (and src/pages/api/**/*.{js,ts})
    3. app/**/route.{js,ts} (and src/app/**/route.{js,ts})
    """
    root = Path(project_dir).resolve()
    endpoints: dict[str, Path] = {}

    # 1. api/**/*.{js,ts,py,go,rs}
    api_dir = root / "api"
    if api_dir.is_dir():
        for p in api_dir.rglob("*"):
            if not p.is_file():
                continue
            rel = p.relative_to(api_dir)
            if is_ignored_file_or_dir(rel):
                continue
            if is_test_or_type_file(p):
                continue
            if p.suffix.lower() in API_EXTENSIONS:
                key = str(p.relative_to(root))
                endpoints[key] = p

    # 2. pages/api/**/*.{js,ts} and src/pages/api/**/*.{js,ts}
    pages_dirs = [root / "pages" / "api", root / "src" / "pages" / "api"]
    for pdir in pages_dirs:
        if pdir.is_dir():
            for p in pdir.rglob("*"):
                if not p.is_file():
                    continue
                rel = p.relative_to(pdir)
                if is_ignored_file_or_dir(rel):
                    continue
                if is_test_or_type_file(p):
                    continue
                if p.suffix.lower() in PAGES_API_EXTENSIONS:
                    key = str(p.relative_to(root))
                    endpoints[key] = p

    # 3. app/**/route.{js,ts} and src/app/**/route.{js,ts}
    app_dirs = [root / "app", root / "src" / "app"]
    for adir in app_dirs:
        if adir.is_dir():
            for p in adir.rglob("*"):
                if not p.is_file():
                    continue
                rel = p.relative_to(adir)
                if is_ignored_file_or_dir(rel):
                    continue
                if is_test_or_type_file(p):
                    continue
                if p.name.lower() in APP_ROUTE_FILENAMES:
                    key = str(p.relative_to(root))
                    endpoints[key] = p

    # Return sorted by relative path
    return [endpoints[k] for k in sorted(endpoints.keys())]


def audit_vercel_functions(project_dir: Path | str) -> Optional[CheckResult]:
    """Audit project for Vercel serverless function limits.

    Returns:
    - None if not a Vercel project (zero noise for other projects).
    - CheckResult with status "passed" if count <= 12.
    - CheckResult with status "warning" if count > 12 (advisory, safe on Pro).
    """
    root = Path(project_dir).resolve()
    if not is_vercel_project(root):
        return None

    start_time = time.perf_counter()
    endpoint_files = count_serverless_functions(root)
    count = len(endpoint_files)
    duration_ms = max(1, int((time.perf_counter() - start_time) * 1000))

    file_locations = [
        FileLocation(
            file=str(p.relative_to(root)),
            message="Serverless function endpoint",
        )
        for p in endpoint_files
    ]

    if count <= VERCEL_HOBBY_FUNCTION_LIMIT:
        status = CheckStatus.PASSED
        summary = f"{count}/{VERCEL_HOBBY_FUNCTION_LIMIT} serverless functions (within Hobby & Pro limits)"
        failure_details: list[str] = []
    else:
        status = CheckStatus.WARNING
        summary = f"{count} serverless functions detected (Safe on Pro; Vercel Hobby allows {VERCEL_HOBBY_FUNCTION_LIMIT})"
        failure_details = [
            f"Detected {count} serverless function endpoints (Vercel Hobby plan limit is {VERCEL_HOBBY_FUNCTION_LIMIT}; Pro allows up to 1000).",
            "Tip: Move internal utilities and database helpers into an '_lib/' directory (e.g. api/_lib/) so Vercel doesn't deploy them as separate functions.",
        ]

    return CheckResult(
        name="platform:vercel",
        layer=CheckLayer.STATIC_HEALTH.value,
        check_type=CheckType.ENV.value,
        command="vibeci-internal:vercel-limits",
        status=status,
        exit_code=0,
        duration_ms=duration_ms,
        summary=summary,
        failure_details=failure_details,
        file_locations=file_locations,
        stdout="",
        stderr="",
    )
