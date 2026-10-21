"""Git change and impact analyzer.

Inspects git diffs, working tree status, and dependency graphs to identify
which files, packages, and tests were affected by the AI's recent code changes.
Enables sub-second verification by focusing only on modified components.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set


@dataclass
class ChangedFilesResult:
    is_git_repo: bool = False
    files: list[Path] = field(default_factory=list)
    relative_files: list[str] = field(default_factory=list)
    affected_directories: set[str] = field(default_factory=set)
    affected_packages: list[str] = field(default_factory=list)
    related_test_files: list[Path] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return len(self.files) > 0


class GitChangeAnalyzer:
    def __init__(self, root_dir: Path):
        self.root_dir = root_dir.resolve()

    def _run_git(self, args: list[str]) -> tuple[int, str]:
        try:
            res = subprocess.run(
                ["git"] + args,
                cwd=str(self.root_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
            )
            return res.returncode, res.stdout.strip()
        except Exception:
            return -1, ""

    def is_git_repo(self) -> bool:
        code, out = self._run_git(["rev-parse", "--is-inside-work-tree"])
        return code == 0 and out == "true"

    def analyze(self, compare_ref: Optional[str] = None) -> ChangedFilesResult:
        if not self.is_git_repo():
            return ChangedFilesResult(is_git_repo=False)

        changed_rel_paths: set[str] = set()

        # 1. Unstaged changes in working tree
        code, out = self._run_git(["diff", "--name-only"])
        if code == 0 and out:
            changed_rel_paths.update(line.strip() for line in out.splitlines() if line.strip())

        # 2. Staged changes
        code, out = self._run_git(["diff", "--name-only", "--cached"])
        if code == 0 and out:
            changed_rel_paths.update(line.strip() for line in out.splitlines() if line.strip())

        # 3. Untracked files (new files created by AI)
        code, out = self._run_git(["status", "--porcelain"])
        if code == 0 and out:
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("??"):
                    fpath = line[3:].strip()
                    # If directory, expand top level files
                    full = self.root_dir / fpath
                    if full.is_dir():
                        for sub in full.rglob("*"):
                            ignored = ("node_modules", ".git", ".venv", "venv", "__pycache__", ".pytest_cache", "dist", "build")
                            if sub.is_file() and not any(p in ignored for p in sub.parts) and not sub.suffix in (".pyc", ".pyo"):
                                changed_rel_paths.add(str(sub.relative_to(self.root_dir)))
                    elif full.is_file():
                        if not any(p in ("__pycache__", ".pytest_cache") for p in full.parts) and not full.suffix in (".pyc", ".pyo"):
                            changed_rel_paths.add(fpath)

        # 4. If working tree is clean and compare_ref is given (e.g. HEAD~1 or origin/main)
        if not changed_rel_paths and compare_ref:
            code, out = self._run_git(["diff", "--name-only", compare_ref])
            if code == 0 and out:
                changed_rel_paths.update(line.strip() for line in out.splitlines() if line.strip())

        # Filter to existing files only
        valid_files: list[Path] = []
        valid_rel_files: list[str] = []
        affected_dirs: set[str] = set()

        for rel in changed_rel_paths:
            full = self.root_dir / rel
            if full.exists() and full.is_file():
                valid_files.append(full)
                valid_rel_files.append(rel)
                # Register top-level or second-level directory (e.g. apps/events or src)
                parts = Path(rel).parts
                if len(parts) >= 2 and parts[0] in ("apps", "packages", "services"):
                    affected_dirs.add(f"{parts[0]}/{parts[1]}")
                elif len(parts) >= 1:
                    affected_dirs.add(parts[0])

        # Find package names in affected monorepo directories
        affected_packages: list[str] = []
        for adir in affected_dirs:
            pkg_file = self.root_dir / adir / "package.json"
            if pkg_file.exists():
                try:
                    data = json.loads(pkg_file.read_text(encoding="utf-8"))
                    if "name" in data:
                        affected_packages.append(data["name"])
                except Exception:
                    pass

        # Find directly related test files
        related_tests: list[Path] = []
        for f in valid_files:
            stem = f.stem
            # If already a test file, include it (only source code files)
            is_test_file = False
            if f.suffix == ".py":
                if stem.startswith("test_") or stem.endswith("_test") or "tests" in f.parts:
                    is_test_file = True
            elif f.suffix in (".js", ".jsx", ".ts", ".tsx", ".mjs"):
                if (
                    any(f.name.endswith(ext) for ext in (".test.js", ".test.jsx", ".test.ts", ".test.tsx", ".spec.js", ".spec.ts", ".spec.jsx", ".spec.tsx"))
                    or "tests" in f.parts
                    or "__tests__" in f.parts
                ):
                    is_test_file = True

            if is_test_file:
                related_tests.append(f)
                continue

            # Look for adjacent test file: foo.test.jsx, foo.test.ts, test_foo.py
            parent = f.parent
            for ext in (".test.js", ".test.jsx", ".test.ts", ".test.tsx", ".spec.ts", ".spec.js"):
                candidate = parent / f"{stem}{ext}"
                if candidate.exists():
                    related_tests.append(candidate)

            if f.suffix == ".py":
                for candidate in (parent / f"test_{stem}.py", parent / f"{stem}_test.py"):
                    if candidate.exists():
                        related_tests.append(candidate)

            # Look in nearby tests/ directory
            tests_dir = parent / "tests"
            if tests_dir.is_dir():
                for candidate in tests_dir.glob(f"*{stem}*"):
                    if candidate.is_file():
                        related_tests.append(candidate)

            # Look in project root tests/ directory
            root_tests = self.root_dir / "tests"
            if root_tests.is_dir():
                for candidate in root_tests.glob(f"*{stem}*"):
                    if candidate.is_file():
                        related_tests.append(candidate)

        return ChangedFilesResult(
            is_git_repo=True,
            files=valid_files,
            relative_files=valid_rel_files,
            affected_directories=affected_dirs,
            affected_packages=affected_packages,
            related_test_files=list(set(related_tests)),
        )
