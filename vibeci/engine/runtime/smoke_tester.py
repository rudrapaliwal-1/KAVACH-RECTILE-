"""Runtime smoke tester.

Boots the application process in a sandboxed background environment, waits for readiness,
checks whether the process crashes on boot, exercises HTTP routes, and ensures clean shutdown.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import List, Optional, Tuple

from vibeci.models import (
    CheckDefinition,
    CheckLayer,
    CheckResult,
    CheckStatus,
    CheckType,
    FileLocation,
)


def is_port_open(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        try:
            s.connect((host, port))
            return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False


class RuntimeSmokeTester:
    def __init__(self, root_dir: Path):
        self.root_dir = root_dir.resolve()

    def _resolve_python(self) -> str:
        import sys
        for venv_name in (".venv", "venv", "env"):
            for bin_dir in ("bin", "Scripts"):
                for py_candidate in ("python", "python.exe"):
                    py_bin = self.root_dir / venv_name / bin_dir / py_candidate
                    if py_bin.exists():
                        return str(py_bin)
        return sys.executable

    def detect_start_command(self) -> Optional[tuple[list[str], int]]:
        """Detect (command_list, target_port)."""
        # 1. JavaScript / TypeScript (package.json)
        pkg_json = self.root_dir / "package.json"
        if pkg_json.exists():
            try:
                data = json.loads(pkg_json.read_text(encoding="utf-8"))
                scripts = data.get("scripts", {})
                # Look for preview or start first, then dev
                for s in ("start", "preview", "serve", "dev:local", "dev"):
                    if s in scripts:
                        return ["npm", "run", s], 3000
            except Exception:
                pass

        # 2. Python Web Frameworks (FastAPI, Flask, Django)
        py = self._resolve_python()

        # Django
        if (self.root_dir / "manage.py").exists():
            return [py, "manage.py", "runserver", "8000", "--noreload"], 8000

        # FastAPI / Flask / Generic entry points
        for entry_file in ("main.py", "app.py", "server.py", "wsgi.py", "asgi.py"):
            entry_path = self.root_dir / entry_file
            if entry_path.exists():
                try:
                    content = entry_path.read_text(encoding="utf-8", errors="ignore")
                    module_name = entry_path.stem
                    if "fastapi" in content.lower():
                        return [py, "-m", "uvicorn", f"{module_name}:app", "--port", "8000"], 8000
                    elif "flask" in content.lower():
                        return [py, entry_file], 5000
                    elif "uvicorn.run" in content:
                        return [py, entry_file], 8000
                except Exception:
                    pass

        return None

    def run_smoke_test(
        self,
        command: Optional[list[str]] = None,
        target_port: int = 3000,
        routes: Optional[list[str]] = None,
        timeout_seconds: int = 15,
    ) -> CheckResult:
        start_time = time.perf_counter()
        probe_routes = routes or ["/"]

        cmd_info = self.detect_start_command() if not command else (command, target_port)
        if not cmd_info:
            return CheckResult(
                name="runtime:smoke",
                layer=CheckLayer.RUNTIME_SMOKE.value,
                check_type=CheckType.SMOKE.value,
                command="none",
                status=CheckStatus.SKIPPED,
                summary="No start or dev script found to exercise runtime boot.",
            )

        cmd, port = cmd_info
        env = os.environ.copy()
        env["PORT"] = str(port)
        env["CI"] = "true"
        env["NODE_ENV"] = "development"

        proc: Optional[subprocess.Popen] = None
        stdout_buf: list[str] = []
        stderr_buf: list[str] = []

        try:
            proc = subprocess.Popen(
                cmd,
                cwd=str(self.root_dir),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                start_new_session=True,
            )

            # Wait for either crash or readiness
            deadline = time.time() + timeout_seconds
            port_ready = False
            crashed = False

            while time.time() < deadline:
                # Check if process exited prematurely
                ret = proc.poll()
                if ret is not None:
                    crashed = True
                    break

                if is_port_open(port):
                    port_ready = True
                    break

                time.sleep(0.5)

            if crashed:
                out, err = proc.communicate(timeout=2)
                combined = (out + "\n" + err).strip()
                err_lines = [l for l in combined.splitlines() if l.strip()][-6:]
                duration_ms = int((time.perf_counter() - start_time) * 1000)
                return CheckResult(
                    name="runtime:smoke",
                    layer=CheckLayer.RUNTIME_SMOKE.value,
                    check_type=CheckType.SMOKE.value,
                    command=" ".join(cmd),
                    status=CheckStatus.FAILED,
                    exit_code=proc.returncode,
                    duration_ms=duration_ms,
                    summary=f"Application crashed on boot (exit code {proc.returncode}).",
                    failure_details=err_lines,
                    stdout=out,
                    stderr=err,
                )

            if not port_ready:
                # Process didn't open port within timeout
                duration_ms = int((time.perf_counter() - start_time) * 1000)
                return CheckResult(
                    name="runtime:smoke",
                    layer=CheckLayer.RUNTIME_SMOKE.value,
                    check_type=CheckType.SMOKE.value,
                    command=" ".join(cmd),
                    status=CheckStatus.TIMED_OUT,
                    duration_ms=duration_ms,
                    summary=f"Application did not open port {port} within {timeout_seconds}s timeout.",
                )

            # Port is ready! Exercise HTTP routes
            failed_routes: list[str] = []
            for route in probe_routes:
                url = f"http://127.0.0.1:{port}{route}"
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "VibeCI-SmokeTest/1.0"})
                    with urllib.request.urlopen(req, timeout=4) as response:
                        code = response.getcode()
                        if code >= 500:
                            failed_routes.append(f"{route} returned HTTP {code}")
                except urllib.error.HTTPError as he:
                    if he.code >= 500:
                        failed_routes.append(f"{route} returned HTTP {he.code}")
                except Exception as ex:
                    # Connection dropped or refused during request
                    failed_routes.append(f"{route} request error: {ex}")

            duration_ms = int((time.perf_counter() - start_time) * 1000)

            if failed_routes:
                return CheckResult(
                    name="runtime:smoke",
                    layer=CheckLayer.RUNTIME_SMOKE.value,
                    check_type=CheckType.SMOKE.value,
                    command=" ".join(cmd),
                    status=CheckStatus.FAILED,
                    exit_code=1,
                    duration_ms=duration_ms,
                    summary=f"Runtime probe failed on {len(failed_routes)} route(s).",
                    failure_details=failed_routes,
                )

            return CheckResult(
                name="runtime:smoke",
                layer=CheckLayer.RUNTIME_SMOKE.value,
                check_type=CheckType.SMOKE.value,
                command=" ".join(cmd),
                status=CheckStatus.PASSED,
                exit_code=0,
                duration_ms=duration_ms,
                summary=f"Application booted cleanly and responded on port {port}.",
            )

        finally:
            # Always ensure clean shutdown of the process group across OS
            if proc and proc.poll() is None:
                try:
                    if hasattr(os, "killpg"):
                        os.killpg(proc.pid, signal.SIGTERM)
                        proc.wait(timeout=3)
                    else:
                        proc.terminate()
                        proc.wait(timeout=3)
                except Exception:
                    try:
                        if hasattr(os, "killpg"):
                            os.killpg(proc.pid, signal.SIGKILL)
                        else:
                            proc.kill()
                    except Exception:
                        pass
