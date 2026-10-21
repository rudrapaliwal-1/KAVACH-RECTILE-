"""Restricted Docker Runner for SENTINEL-X Verification (Layer 5).

Provides ephemeral, non-root, isolated execution for candidate patches:
1. Validates request, patch syntax, file scope, and exact hash binding.
2. Checks trusted backend ApprovalVerifier gate before any workspace creation.
3. Pre-flight checks Docker daemon availability without falling back to host execution.
4. Copies clean baseline avoiding symlink traversal.
5. Applies patch deterministically using atomic non-interactive patch tool.
6. Mounts protected tests strictly READ-ONLY (:ro).
7. Runs Pytest in disposable Docker container with restricted network, CPU, memory, capabilities, and read-only rootfs.
8. Evaluates results through independent, tamper-resistant TestResultEvaluator.
"""

from __future__ import annotations

import asyncio
import inspect
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Optional, Sequence

from .contracts import (
    ApprovalVerifier,
    VerificationRequest,
    VerificationResult,
    VerificationStatus,
)
from .evaluator import TestResultEvaluator
from .patch_validator import PatchValidator, PatchValidationError


def sanitize_log(text: str) -> str:
    """Sanitize execution logs before exposing to AI or orchestrator."""
    if not text:
        return ""
    # Strip local host user paths
    sanitized = re.sub(r"/home/[^/\s]+/[^/\s]+", "/workspace", text)
    # Redact potential sensitive tokens/keys
    sanitized = re.sub(
        r"(token|secret|password|auth|key)[:=]\s*([^\s]+)",
        r"\1: [REDACTED]",
        sanitized,
        flags=re.IGNORECASE,
    )
    return sanitized


def check_docker_available() -> tuple[bool, str]:
    """Verify that Docker binary and daemon are operational without executing user code."""
    try:
        from backend.safe_cache import safe_cache
        return safe_cache.get_or_check_docker_preflight(_raw_check_docker_available, ttl_seconds=60.0)
    except Exception:
        return _raw_check_docker_available()


def _raw_check_docker_available() -> tuple[bool, str]:
    if not shutil.which("docker"):
        return False, "Docker binary not found on host system."
    try:
        proc = subprocess.run(
            ["docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5.0,
        )
        if proc.returncode != 0:
            return False, f"Docker daemon is not reachable: {proc.stderr.strip()}"
        return True, ""
    except Exception as exc:
        return False, f"Docker availability check failed: {exc}"


async def execute_approval(verifier: ApprovalVerifier, patch_hash: str, approval_id: str) -> bool:
    """Safely execute sync or async ApprovalVerifier callback."""
    if not callable(verifier):
        return False
    try:
        res = verifier(patch_hash, approval_id)
        if inspect.isawaitable(res):
            return bool(await res)
        return bool(res)
    except Exception:
        return False


async def verify_patch(
    request: VerificationRequest,
    approval_verifier: ApprovalVerifier,
    docker_image: str = "sentinel-verification-lab:latest",
) -> VerificationResult:
    """Execute end-to-end patch verification in a restricted disposable Docker sandbox."""
    start_time = time.time()
    job_id = request.job_id or "job-unknown"
    patch_hash = request.patch_hash or PatchValidator.compute_hash(request.patch_text)
    run_id = request.run_id or f"run_{uuid.uuid4().hex[:12]}"
    patch_id = request.patch_id or ""

    # 1. Target Application Authorization Check
    if request.target_app_id != "bola-demo-v1" and not (request.source_root and re.fullmatch(r"project-[0-9a-f]{32}", request.target_app_id)):
        return VerificationResult(
            job_id=job_id,
            patch_hash=patch_hash,
            status=VerificationStatus.POLICY_REJECTED.value,
            execution_error=f"Unsupported target_app_id: '{request.target_app_id}'. Expected 'bola-demo-v1'.",
            run_id=run_id,
            patch_id=patch_id,
        )

    # 2. Patch Validation (exact hash, scope, syntax, size, traversal, prohibited ops)
    try:
        PatchValidator.validate_patch(request.patch_text, request.patch_hash)
    except PatchValidationError as exc:
        return VerificationResult(
            job_id=job_id,
            patch_hash=patch_hash,
            status=VerificationStatus.POLICY_REJECTED.value,
            execution_error=f"Patch policy rejected: {exc}",
            run_id=run_id,
            patch_id=patch_id,
        )

    # 3. Human Approval Gate Verification (Fail-closed)
    is_approved = await execute_approval(approval_verifier, patch_hash, request.approval_id)
    if not is_approved:
        return VerificationResult(
            job_id=job_id,
            patch_hash=patch_hash,
            status=VerificationStatus.POLICY_REJECTED.value,
            execution_error="Missing or invalid approval signature/id from backend gate.",
            run_id=run_id,
            patch_id=patch_id,
        )

    # 4. Pre-flight Docker Availability Check (No fallback to host execution!)
    docker_ok, docker_err = check_docker_available()
    if not docker_ok:
        return VerificationResult(
            job_id=job_id,
            patch_hash=patch_hash,
            status=VerificationStatus.EXECUTION_ERROR.value,
            duration_ms=int((time.time() - start_time) * 1000),
            execution_error=f"Sandbox infrastructure unavailable: {docker_err}",
            run_id=run_id,
            patch_id=patch_id,
        )

    # 5. Prepare Isolated Ephemeral Workspace
    base_dir = Path(__file__).resolve().parent
    lab_app_src = (Path(request.source_root) if request.source_root else base_dir / "lab") / "app"
    protected_tests_src = base_dir / "protected_tests"

    tmp_root = base_dir / ".tmp"
    tmp_root.mkdir(parents=True, exist_ok=True)
    temp_dir = tempfile.mkdtemp(dir=str(tmp_root), prefix=f"sentinel_{job_id}_")
    container_id = f"sentinel_run_{uuid.uuid4().hex[:12]}"

    try:
        workspace_dir = Path(temp_dir)
        app_dest = workspace_dir / "verification" / "lab" / "app"
        app_dest.parent.mkdir(parents=True, exist_ok=True)
        # Copy baseline without following symlinks
        if request.source_root:
            app_dest.mkdir()
            for name in ("__init__.py", "access.py", "sample_data.py"):
                src = lab_app_src / name
                if not src.is_file() or src.is_symlink() or src.stat().st_size > 2 * 1024 * 1024:
                    return VerificationResult(job_id=job_id, patch_hash=patch_hash,
                        status=VerificationStatus.EXECUTION_ERROR.value,
                        execution_error="Uploaded contract source is invalid.", run_id=run_id, patch_id=patch_id)
                fd = os.open(src, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                try:
                    with os.fdopen(fd, "rb") as source, (app_dest / name).open("xb") as out:
                        shutil.copyfileobj(source, out, length=65536)
                finally:
                    pass
        else:
            shutil.copytree(lab_app_src, app_dest, symlinks=False)

        tests_dest = workspace_dir / "verification" / "protected_tests"
        shutil.copytree(protected_tests_src, tests_dest, symlinks=False)

        report_dir = workspace_dir / "report"
        report_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(temp_dir, 0o777)
        os.chmod(report_dir, 0o777)
        report_file_host = report_dir / "test_report.json"

        # 6. Apply Candidate Patch to Clean Baseline Deterministically
        target_access_file = app_dest / "access.py"
        if target_access_file.is_symlink() or not target_access_file.is_file():
            return VerificationResult(
                job_id=job_id,
                patch_hash=patch_hash,
                status=VerificationStatus.EXECUTION_ERROR.value,
                duration_ms=int((time.time() - start_time) * 1000),
                execution_error="Security error: Baseline target file is invalid or a symlink.",
                run_id=run_id,
                patch_id=patch_id,
            )

        patch_file = workspace_dir / "candidate.patch"
        patch_file.write_text(request.patch_text, encoding="utf-8")

        # Deterministic patch application: strict -p1 forward batch mode
        apply_proc = subprocess.run(
            ["patch", "-p1", "--batch", "--forward", "--input", str(patch_file)],
            cwd=str(workspace_dir / "verification" / "lab"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10.0,
        )

        if apply_proc.returncode != 0:
            return VerificationResult(
                job_id=job_id,
                patch_hash=patch_hash,
                status=VerificationStatus.EXECUTION_ERROR.value,
                duration_ms=int((time.time() - start_time) * 1000),
                execution_error=f"Patch application failed:\n{apply_proc.stderr or apply_proc.stdout}",
                run_id=run_id,
                patch_id=patch_id,
            )

        # Post-patch symlink integrity check
        if target_access_file.is_symlink() or not target_access_file.is_file():
            return VerificationResult(
                job_id=job_id,
                patch_hash=patch_hash,
                status=VerificationStatus.EXECUTION_ERROR.value,
                duration_ms=int((time.time() - start_time) * 1000),
                execution_error="Security violation: Applied patch converted target into a symlink.",
                run_id=run_id,
                patch_id=patch_id,
            )

        # 7. Execute Restricted Sandbox Container with Ephemeral Attestation Token
        run_token = secrets.token_hex(32)
        docker_cmd = [
            "docker", "run",
            "--name", container_id,
            "--rm",
            "--network", "none",
            "--memory", "512m",
            "--cpus", "1.0",
            "--pids-limit", "64",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            "-e", "VERIFICATION_REPORT_PATH=/workspace/report/test_report.json",
            "-e", f"VERIFICATION_RUN_TOKEN={run_token}",
            "-e", f"VERIFICATION_EXPECTED_HASH={patch_hash}",
            "-e", f"VERIFICATION_JOB_ID={job_id}",
            "-e", f"VERIFICATION_RUN_ID={run_id}",
            "-e", "PYTHONPATH=/workspace",
            "-e", "PYTHONDONTWRITEBYTECODE=1",
            "-e", "PYTHONUNBUFFERED=1",
            "-v", f"{app_dest}:/workspace/verification/lab/app:ro",
            "-v", f"{tests_dest}:/workspace/verification/protected_tests:ro",
            "-v", f"{report_dir}:/workspace/report:rw",
            docker_image,
            "pytest", "-p", "no:cacheprovider", "/workspace/verification/protected_tests", "-v",
        ]

        timed_out = False
        raw_output = ""
        exit_code = 0
        runner_error = None

        try:
            proc = await asyncio.create_subprocess_exec(
                *docker_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_data, stderr_data = await asyncio.wait_for(
                proc.communicate(),
                timeout=float(request.timeout_seconds),
            )
            exit_code = proc.returncode if proc.returncode is not None else 1
            # Bounded output decoding (max 512 KB)
            out_str = stdout_data[:524288].decode("utf-8", errors="replace")
            err_str = stderr_data[:524288].decode("utf-8", errors="replace")
            raw_output = f"{out_str}\n{err_str}"
        except asyncio.TimeoutError:
            timed_out = True
            exit_code = -1
            raw_output = f"Execution timed out after {request.timeout_seconds}s."
            subprocess.run(["docker", "kill", container_id], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as exc:
            runner_error = str(exc)
            exit_code = 1

        duration_ms = int((time.time() - start_time) * 1000)

        # 8. Read Test Report Safely
        report_json_str = None
        if report_file_host.exists():
            if report_file_host.is_symlink():
                runner_error = "Security error: Test report is a symbolic link."
            elif report_file_host.stat().st_size > 1048576:  # 1 MB limit
                runner_error = "Security error: Test report exceeds maximum permitted size."
            else:
                report_json_str = report_file_host.read_text(encoding="utf-8")

        # 9. Evaluate Evidence with Deterministic Evaluator
        return TestResultEvaluator.evaluate(
            job_id=job_id,
            patch_hash=patch_hash,
            exit_code=exit_code,
            raw_output=sanitize_log(raw_output),
            report_json_str=report_json_str,
            duration_ms=duration_ms,
            timed_out=timed_out,
            runner_error=sanitize_log(runner_error) if runner_error else None,
            run_id=run_id,
            patch_id=patch_id,
            run_token=run_token,
        )

    finally:
        # Guaranteed cleanup of container and ephemeral workspace
        subprocess.run(["docker", "rm", "-f", container_id], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        shutil.rmtree(temp_dir, ignore_errors=True)
