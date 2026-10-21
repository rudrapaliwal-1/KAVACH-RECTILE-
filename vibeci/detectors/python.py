"""Detector for Python projects and tools (pytest, ruff, mypy, flake8)."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import List, Optional

from vibeci.detectors.base import BaseDetector
from vibeci.models import CheckDefinition, CheckType


class PythonDetector(BaseDetector):
    name: str = "python"

    def is_applicable(self, root_dir: Path) -> bool:
        indicators = [
            "pyproject.toml",
            "setup.py",
            "setup.cfg",
            "requirements.txt",
            "Pipfile",
            "tox.ini",
            ".python-version",
        ]
        if any((root_dir / ind).exists() for ind in indicators):
            return True

        # Check if there are any .py files in the root or top-level dirs
        try:
            for item in root_dir.iterdir():
                if item.is_file() and item.suffix == ".py":
                    return True
                if item.is_dir() and not item.name.startswith(".") and item.name not in ("node_modules", "dist", "build"):
                    if any(sub.is_file() and sub.suffix == ".py" for sub in item.iterdir()):
                        return True
        except PermissionError:
            pass
        return False

    def _resolve_python_runner(self, root_dir: Path, tool: str) -> list[str]:
        """Resolve the safest and most accurate way to run the tool."""
        import sys
        # 1. Check local virtual environment (.venv, venv, env)
        for venv_name in (".venv", "venv", "env"):
            for bin_dir in ("bin", "Scripts"):
                venv_bin = root_dir / venv_name / bin_dir
                tool_path = venv_bin / tool
                tool_exe = venv_bin / f"{tool}.exe"
                if tool_path.exists() and tool_path.is_file():
                    return [str(tool_path)]
                if tool_exe.exists() and tool_exe.is_file():
                    return [str(tool_exe)]
                for py_candidate in ("python", "python.exe"):
                    py_path = venv_bin / py_candidate
                    if py_path.exists() and py_path.is_file():
                        return [str(py_path), "-m", tool]

        # 2. Check if uv is present and project has pyproject.toml
        if (root_dir / "pyproject.toml").exists() and shutil.which("uv"):
            return ["uv", "run", tool]

        # 3. Check system tool executable
        if shutil.which(tool):
            return [tool]

        # 4. Fallback to current Python interpreter
        fallback_py = shutil.which("python3") or shutil.which("python") or sys.executable
        return [fallback_py, "-m", tool]

    def detect(self, root_dir: Path) -> list[CheckDefinition]:
        checks: list[CheckDefinition] = []

        # Read pyproject.toml if present
        pyproject_content = ""
        pyproject_file = root_dir / "pyproject.toml"
        if pyproject_file.exists():
            try:
                pyproject_content = pyproject_file.read_text(encoding="utf-8")
            except Exception:
                pass

        # 1. Detect pytest
        has_tests_dir = any((root_dir / d).is_dir() for d in ("tests", "test"))
        has_test_files = False
        if not has_tests_dir:
            try:
                has_test_files = any(
                    f.is_file() and (f.name.startswith("test_") or f.name.endswith("_test.py"))
                    for f in root_dir.glob("*.py")
                )
            except Exception:
                pass

        has_pytest_config = (
            (root_dir / "pytest.ini").exists()
            or "[tool.pytest" in pyproject_content
            or (root_dir / "setup.cfg").exists()
            and "pytest" in (root_dir / "setup.cfg").read_text(errors="ignore")
        )

        if has_tests_dir or has_test_files or has_pytest_config:
            cmd = self._resolve_python_runner(root_dir, "pytest")
            checks.append(
                CheckDefinition(
                    name="pytest",
                    command=cmd,
                    check_type=CheckType.TEST,
                    cwd=root_dir,
                    description="Run Python test suite with pytest",
                    required=True,
                    discovered_by="python-detector",
                )
            )

        # 2. Detect ruff
        has_ruff_config = (
            (root_dir / "ruff.toml").exists()
            or (root_dir / ".ruff.toml").exists()
            or "[tool.ruff" in pyproject_content
        )
        # Check if ruff binary or dependency is mentioned
        has_ruff_dep = "ruff" in pyproject_content or (root_dir / ".venv" / "bin" / "ruff").exists()
        if has_ruff_config or has_ruff_dep:
            cmd = self._resolve_python_runner(root_dir, "ruff")
            if cmd[-1] == "ruff":
                cmd = cmd + ["check", "."]
            else:
                cmd = cmd + ["check", "."]
            checks.append(
                CheckDefinition(
                    name="ruff",
                    command=cmd,
                    check_type=CheckType.LINT,
                    cwd=root_dir,
                    description="Lint Python code with ruff",
                    required=True,
                    discovered_by="python-detector",
                )
            )

        # 3. Detect mypy
        has_mypy_config = (
            (root_dir / "mypy.ini").exists()
            or (root_dir / ".mypy.ini").exists()
            or "[tool.mypy" in pyproject_content
        )
        has_mypy_dep = "mypy" in pyproject_content or (root_dir / ".venv" / "bin" / "mypy").exists()
        if has_mypy_config or has_mypy_dep:
            cmd = self._resolve_python_runner(root_dir, "mypy")
            cmd = cmd + ["."]
            checks.append(
                CheckDefinition(
                    name="mypy",
                    command=cmd,
                    check_type=CheckType.TYPECHECK,
                    cwd=root_dir,
                    description="Type check Python code with mypy",
                    required=True,
                    discovered_by="python-detector",
                )
            )

        # 4. Detect flake8 (if ruff is not already present)
        if not any(c.name == "ruff" for c in checks):
            has_flake8_config = (root_dir / ".flake8").exists()
            if has_flake8_config:
                cmd = self._resolve_python_runner(root_dir, "flake8")
                checks.append(
                    CheckDefinition(
                        name="flake8",
                        command=cmd,
                        check_type=CheckType.LINT,
                        cwd=root_dir,
                        description="Lint Python code with flake8",
                        required=True,
                        discovered_by="python-detector",
                    )
                )

        return checks
