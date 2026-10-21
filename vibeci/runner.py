"""Execution coordinator for running checks, parsing output, and caching results."""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from vibeci.config import VibeConfig
from vibeci.models import (
    CheckDefinition,
    CheckResult,
    CheckStatus,
    FileLocation,
    OverallStatus,
    VerificationReport,
)

CACHE_DIR_NAME = ".vibeci"
CACHE_FILE_NAME = "last_run.json"


class CheckRunner:
    def __init__(self, root_dir: Path, config: Optional[VibeConfig] = None):
        self.root_dir = root_dir.resolve()
        self.config = config or VibeConfig.load(self.root_dir)

    def run_check(self, check: CheckDefinition, timeout_seconds: Optional[int] = None) -> CheckResult:
        timeout = timeout_seconds or check.timeout_seconds or self.config.timeout_seconds
        cwd = check.cwd or self.root_dir

        start_time = time.perf_counter()
        exit_code: Optional[int] = None
        stdout = ""
        stderr = ""
        status = CheckStatus.PASSED

        # Prepare non-interactive environment
        env = os.environ.copy()
        env["CI"] = "true"
        env["CONTINUOUS_INTEGRATION"] = "true"
        env["DEBIAN_FRONTEND"] = "noninteractive"
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["PAGER"] = "cat"
        env["JEST_WORKER_ID"] = "1"
        env["WATCH"] = "false"
        env["NODE_ENV"] = env.get("NODE_ENV", "test")

        # Resolve command executable across OS (e.g. npm.cmd on Windows)
        cmd = list(check.command)
        if cmd and not Path(cmd[0]).is_file():
            resolved = shutil.which(cmd[0])
            if resolved:
                cmd[0] = resolved

        # Windows start_new_session / creationflags handling
        popen_kwargs: dict = {
            "cwd": str(cwd),
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "text": True,
            "env": env,
        }
        if os.name != "nt":
            popen_kwargs["start_new_session"] = True

        try:
            # Run process with stdin closed to prevent interactive prompt hanging
            proc = subprocess.Popen(cmd, **popen_kwargs)
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
                exit_code = proc.returncode
                status = CheckStatus.PASSED if exit_code == 0 else CheckStatus.FAILED
            except subprocess.TimeoutExpired:
                # Terminate the entire process tree across OS
                try:
                    if hasattr(os, "killpg"):
                        os.killpg(proc.pid, signal.SIGKILL)
                    else:
                        proc.kill()
                except Exception:
                    proc.kill()
                try:
                    stdout, stderr = proc.communicate(timeout=2)
                except Exception:
                    pass
                status = CheckStatus.TIMED_OUT
                exit_code = -1
        except FileNotFoundError as fnf:
            status = CheckStatus.ERROR
            stderr = f"Command executable not found: {check.command[0] if check.command else ''} ({fnf})"
            exit_code = 127
        except Exception as ex:
            status = CheckStatus.ERROR
            stderr = f"Execution error: {ex}"
            exit_code = 1

        duration_ms = int((time.perf_counter() - start_time) * 1000)

        # Parse summaries, snippets, file locations
        summary, failure_details, file_locations = self._extract_failure_info(
            check, status, stdout, stderr
        )

        layer_val = getattr(check.layer, "value", str(check.layer)) if hasattr(check, "layer") else "custom"
        return CheckResult(
            name=check.name,
            layer=layer_val,
            check_type=check.check_type.value,
            command=check.display_command,
            status=status,
            exit_code=exit_code,
            duration_ms=duration_ms,
            stdout=stdout,
            stderr=stderr,
            summary=summary,
            failure_details=failure_details,
            file_locations=file_locations,
        )

    def _extract_failure_info(
        self,
        check: CheckDefinition,
        status: CheckStatus,
        stdout: str,
        stderr: str,
    ) -> tuple[str, list[str], list[FileLocation]]:
        combined = stdout + "\n" + stderr
        lines = [line.strip() for line in combined.splitlines() if line.strip()]

        summary = ""
        failure_details: list[str] = []
        file_locations: list[FileLocation] = []

        if status == CheckStatus.PASSED:
            # Extract positive summaries if available
            for line in reversed(lines):
                if any(kw in line.lower() for kw in ("passed", "success", "all checks passed")):
                    summary = line
                    break
            if not summary:
                summary = "All checks passed successfully."
            return summary, [], []

        if status == CheckStatus.TIMED_OUT:
            summary = f"Check timed out after {check.timeout_seconds or self.config.timeout_seconds}s"
            failure_details.append(summary)
            return summary, failure_details, []

        if status == CheckStatus.ERROR:
            summary = stderr.splitlines()[0] if stderr else "Command execution error"
            failure_details.append(summary)
            return summary, failure_details, []

        # Extract file locations and messages using regular expressions
        # Pattern 1: path/to/file.ext:line:col: message (Ruff, ESLint, Biome, GCC-style)
        pattern_gcc = re.compile(r"^([\w\-.\\/]+(?:\.[\w]+)):(\d+)(?::(\d+))?[:\s]+(.*)$")
        # Pattern 2: TypeScript style: path/file.ts(line,col): error ... or path/file.ts:line:col - error TS...
        pattern_tsc = re.compile(r"^([\w\-.\\/]+(?:\.[\w]+)):(\d+):(\d+)\s*-\s*error\s*(.*)$")
        # Pattern 3: Pytest: FAILED path/to/test.py::test_name - Reason
        pattern_pytest_failed = re.compile(r"^FAILED\s+([\w\-.\\/]+)::([\w]+)(?:\s*-\s*(.*))?$")
        # Pattern 4: Python traceback File "...":line in func
        pattern_traceback = re.compile(r'File "([^"]+)", line (\d+)(?:, in (\w+))?')

        found_locations: list[FileLocation] = []

        for line in lines:
            # Check pytest summary line
            if "=====" in line and ("failed" in line or "passed" in line or "error" in line):
                summary = line.replace("=", "").strip()

            # Pytest failed items
            m_py = pattern_pytest_failed.match(line)
            if m_py:
                fpath, test_fn, reason = m_py.group(1), m_py.group(2), m_py.group(3) or ""
                found_locations.append(
                    FileLocation(
                        file=fpath,
                        message=f"{test_fn}: {reason}" if reason else test_fn,
                    )
                )
                failure_details.append(line)
                continue

            # TypeScript
            m_tsc = pattern_tsc.match(line)
            if m_tsc:
                fpath, lnum, cnum, msg = m_tsc.group(1), int(m_tsc.group(2)), int(m_tsc.group(3)), m_tsc.group(4)
                found_locations.append(FileLocation(file=fpath, line=lnum, column=cnum, message=msg))
                failure_details.append(f"{fpath}:{lnum}:{cnum} - {msg}")
                continue

            # Standard gcc/lint format
            m_gcc = pattern_gcc.match(line)
            if m_gcc:
                fpath, lnum, cnum, msg = (
                    m_gcc.group(1),
                    int(m_gcc.group(2)),
                    int(m_gcc.group(3)) if m_gcc.group(3) else None,
                    m_gcc.group(4),
                )
                if any(fpath.endswith(ext) for ext in (".py", ".ts", ".tsx", ".js", ".jsx", ".json", ".vue", ".svelte")):
                    found_locations.append(FileLocation(file=fpath, line=lnum, column=cnum, message=msg))
                    failure_details.append(f"{fpath}:{lnum} - {msg}")
                    continue

            # Python traceback
            m_tb = pattern_traceback.search(line)
            if m_tb:
                fpath, lnum, func = m_tb.group(1), int(m_tb.group(2)), m_tb.group(3)
                if not fpath.startswith("<"):
                    found_locations.append(
                        FileLocation(
                            file=fpath,
                            line=lnum,
                            message=f"in {func}" if func else None,
                        )
                    )

        # De-duplicate file locations preserving order
        unique_locations: list[FileLocation] = []
        seen = set()
        for loc in found_locations:
            key = (loc.file, loc.line, loc.column)
            if key not in seen:
                seen.add(key)
                unique_locations.append(loc)

        if not summary:
            # Fallback summary: last non-empty line
            summary = lines[-1] if lines else "Check returned non-zero exit status."

        # If failure details is empty, include the last few relevant lines
        if not failure_details:
            failure_details = lines[-8:] if len(lines) > 8 else lines

        return summary, failure_details[:10], unique_locations[:10]

    def run_all(
        self,
        checks: list[CheckDefinition],
        project_type: str = "auto",
        fail_fast: bool = False,
        timeout_seconds: Optional[int] = None,
        only_checks: Optional[list[str]] = None,
        failed_only: bool = False,
        on_start: Optional[Callable[[CheckDefinition], None]] = None,
        on_complete: Optional[Callable[[CheckResult], None]] = None,
    ) -> VerificationReport:
        # Filter checks if failed_only requested
        if failed_only:
            last_failed_names = self.get_last_failed_check_names()
            if last_failed_names:
                checks = [c for c in checks if c.name in last_failed_names]
            else:
                checks = []

        # Filter if only_checks specified
        if only_checks:
            checks = [c for c in checks if c.name in only_checks]

        # Ignore checks configured in settings
        checks = [c for c in checks if c.name not in self.config.ignore_checks]

        start_time = time.perf_counter()
        results: list[CheckResult] = []

        report = VerificationReport(
            project_name=self.root_dir.name,
            project_type=project_type,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        for check in checks:
            if on_start:
                on_start(check)

            res = self.run_check(check, timeout_seconds=timeout_seconds)
            results.append(res)

            if on_complete:
                on_complete(res)

            if fail_fast or self.config.fail_fast:
                if res.status in (CheckStatus.FAILED, CheckStatus.ERROR, CheckStatus.TIMED_OUT):
                    break

        report.checks = results
        report.total_duration_ms = int((time.perf_counter() - start_time) * 1000)
        report.compute_status()

        # Save cache for repeat runs / --failed-only
        self._save_cache(report)

        return report

    def _get_cache_path(self) -> Path:
        return self.root_dir / CACHE_DIR_NAME / CACHE_FILE_NAME

    def _save_cache(self, report: VerificationReport) -> None:
        try:
            cache_dir = self.root_dir / CACHE_DIR_NAME
            cache_dir.mkdir(exist_ok=True)
            self._get_cache_path().write_text(report.to_json(), encoding="utf-8")
        except Exception:
            pass

    def get_last_failed_check_names(self) -> list[str]:
        cache_path = self._get_cache_path()
        if not cache_path.exists():
            return []
        try:
            data = json.loads(cache_path.read_text(encoding="utf-8"))
            return [
                c["name"]
                for c in data.get("checks", [])
                if c.get("status") in ("failed", "error", "timed_out")
            ]
        except Exception:
            return []
