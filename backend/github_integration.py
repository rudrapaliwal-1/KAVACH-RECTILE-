"""SENTINEL-X GitHub Pull Request Verification Integration.

Binds the existing SENTINEL-X verification pipeline to GitHub Pull Requests without
creating a parallel verification system.

Invariants:
1. Minimum necessary permissions: repository-level read (PR/contents) and status write.
2. Source & patch integrity: bound to exact commit SHA and repository.
3. Untrusted PR code is NEVER executed on the host. Isolated verifier (Docker/sandbox) only.
4. Incoming webhooks are strictly authenticated with HMAC-SHA256 (X-Hub-Signature-256).
5. Webhook delivery idempotency via X-GitHub-Delivery.
6. A passing result never automatically grants human approval unless policy explicitly allows it.
7. Stale results are rejected if PR updates during verification; new commits trigger re-verification.
8. Every status links directly to the immutable SENTINEL-X evidence report.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.error import HTTPError
from urllib.request import Request as URLRequest, urlopen
from uuid import uuid4

from .candidates import parse_and_validate_unified_diff
from .config import Settings
from .database import Database
from .manifest import TARGET_MANIFEST
from .models import Status, WorkflowError
from .policy import patch_hash, validate_patch
from verification.patch_validator import PatchValidator, PatchValidationError

logger = logging.getLogger("sentinel_x.github")

COMMIT_SHA_REGEX = re.compile(r"^[0-9a-fA-F]{40}$")
REPO_NAME_REGEX = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex}"


def verify_github_signature(raw_payload: bytes, signature_header: Optional[str], secret: str) -> bool:
    """Authenticates GitHub webhook delivery using HMAC-SHA256.
    
    Prevents unauthenticated payloads or spoofed repository URLs.
    """
    if not secret or not signature_header:
        return False

    if not signature_header.startswith("sha256="):
        return False

    expected_sig = "sha256=" + hmac.new(
        secret.encode("utf-8"),
        raw_payload,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected_sig, signature_header)


def is_repo_authorized(repo_full_name: str, allowed_repos_config: str) -> bool:
    """Validates repository name against configuration using principle of least privilege."""
    if not REPO_NAME_REGEX.match(repo_full_name):
        return False

    allowed_repos_config = (allowed_repos_config or "").strip()
    if not allowed_repos_config or allowed_repos_config == "*":
        return True

    allowed_set = {r.strip().lower() for r in allowed_repos_config.split(",") if r.strip()}
    return repo_full_name.lower() in allowed_set


class GitHubClient:
    """Scoped HTTP client for GitHub API with rate-limit and error handling."""

    def __init__(self, token: str = "", base_url: str = "https://api.github.com"):
        self.token = token
        self.base_url = base_url.rstrip("/")
        self.published_statuses: List[Dict[str, Any]] = []

    def post_commit_status(
        self,
        repo: str,
        sha: str,
        state: str,
        description: str,
        target_url: str,
        context: str = "sentinel-x/verification",
    ) -> Dict[str, Any]:
        """Publishes commit status (pending, success, failure, error) to GitHub."""
        record = {
            "repo": repo,
            "sha": sha,
            "state": state,
            "description": description[:140],
            "target_url": target_url,
            "context": context,
            "timestamp": _utc_now(),
        }
        self.published_statuses.append(record)

        if not self.token:
            logger.info("GitHub token not configured; recorded commit status locally: %s", record)
            return {"status": "recorded_offline", **record}

        url = f"{self.base_url}/repos/{repo}/statuses/{sha}"
        payload = json.dumps({
            "state": state,
            "target_url": target_url,
            "description": description[:140],
            "context": context,
        }).encode("utf-8")

        req = URLRequest(url, data=payload, method="POST")
        req.add_header("Authorization", f"Bearer {self.token}")
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", "Sentinel-X-Verification/1.0")

        try:
            with urlopen(req, timeout=10.0) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except HTTPError as err:
            remaining = err.headers.get("X-RateLimit-Remaining")
            reset_time = err.headers.get("X-RateLimit-Reset")
            if err.code in (403, 429) and remaining == "0":
                logger.warning("GitHub API rate limit exceeded. Reset at %s", reset_time)
                return {"error": "rate_limited", "reset_time": reset_time, "code": err.code}
            logger.error("GitHub API status post failed with HTTP %d: %s", err.code, err.reason)
            return {"error": "http_error", "code": err.code, "reason": str(err.reason)}
        except Exception as err:
            logger.error("GitHub API network error: %s", err)
            return {"error": "network_error", "detail": str(err)}

    def fetch_pull_request_diff(self, repo: str, pr_number: int) -> str:
        """Retrieves raw unified diff for a pull request."""
        if not self.token:
            return ""

        url = f"{self.base_url}/repos/{repo}/pulls/{pr_number}"
        req = URLRequest(url, method="GET")
        req.add_header("Authorization", f"Bearer {self.token}")
        req.add_header("Accept", "application/vnd.github.v3.diff")
        req.add_header("User-Agent", "Sentinel-X-Verification/1.0")

        try:
            with urlopen(req, timeout=10.0) as resp:
                return resp.read().decode("utf-8")
        except HTTPError as err:
            logger.error("Failed to fetch PR diff (HTTP %d): %s", err.code, err.reason)
            raise WorkflowError(f"GitHub diff retrieval failed: {err.reason}", 502, "GITHUB_DIFF_ERROR") from err
        except Exception as err:
            logger.error("Network error fetching PR diff: %s", err)
            raise WorkflowError(f"GitHub diff network error: {str(err)}", 502, "GITHUB_NETWORK_ERROR") from err


class GitHubPRCoordinator:
    """Orchestrates Pull Request intake, verification binding, and status publishing."""

    def __init__(
        self,
        db: Database,
        settings: Settings,
        workflow: Any,
        client: Optional[GitHubClient] = None,
    ):
        self.db = db
        self.settings = settings
        self.workflow = workflow
        self.client = client or GitHubClient(token=settings.github_token)

    def process_webhook(
        self,
        raw_payload: bytes,
        headers: Dict[str, str],
        custom_diff: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Main entry point for incoming GitHub webhook requests."""
        # 1. Authenticate Signature
        signature_header = headers.get("x-hub-signature-256") or headers.get("X-Hub-Signature-256")
        if not verify_github_signature(raw_payload, signature_header, self.settings.github_webhook_secret):
            raise WorkflowError(
                "Invalid or missing GitHub webhook signature",
                401,
                "WEBHOOK_SIGNATURE_INVALID",
            )

        # 2. Check Idempotency / Deduplicate Deliveries
        delivery_id = headers.get("x-github-delivery") or headers.get("X-GitHub-Delivery") or ""
        event_type = headers.get("x-github-event") or headers.get("X-GitHub-Event") or ""

        if not delivery_id:
            raise WorkflowError("Missing X-GitHub-Delivery header", 400, "MISSING_DELIVERY_ID")

        try:
            data = json.loads(raw_payload.decode("utf-8"))
        except Exception as err:
            raise WorkflowError("Malformed JSON webhook payload", 400, "MALFORMED_JSON") from err

        repo_info = data.get("repository") or {}
        repo_full_name = repo_info.get("full_name") or ""

        with self.db.transaction() as db:
            existing_delivery = db.execute(
                "SELECT delivery_id FROM github_deliveries WHERE delivery_id = ?",
                (delivery_id,),
            ).fetchone()
            if existing_delivery:
                logger.info("Ignoring duplicate webhook delivery %s", delivery_id)
                return {"status": "duplicate_ignored", "delivery_id": delivery_id}

            db.execute(
                "INSERT INTO github_deliveries (delivery_id, event_type, repo_full_name, received_at) VALUES (?, ?, ?, ?)",
                (delivery_id, event_type, repo_full_name, _utc_now()),
            )

        # 3. Filter for pull_request events
        if event_type != "pull_request":
            return {"status": "ignored_event_type", "event": event_type}

        action = data.get("action")
        pr_data = data.get("pull_request") or {}
        pr_number = pr_data.get("number")
        base_sha = (pr_data.get("base") or {}).get("sha")
        head_sha = (pr_data.get("head") or {}).get("sha")

        if not pr_number or not base_sha or not head_sha:
            raise WorkflowError("Incomplete pull request metadata", 400, "INCOMPLETE_PR_METADATA")

        # 4. Validate Repository Authorization
        if not is_repo_authorized(repo_full_name, self.settings.github_allowed_repositories):
            raise WorkflowError(
                f"Repository '{repo_full_name}' is not authorized for SENTINEL-X verification",
                403,
                "UNAUTHORIZED_REPOSITORY",
            )

        # 5. Validate Commit Identity
        if not COMMIT_SHA_REGEX.match(base_sha) or not COMMIT_SHA_REGEX.match(head_sha):
            raise WorkflowError("Invalid commit SHA format", 400, "INVALID_COMMIT_SHA")

        # 6. Handle Closed Pull Requests
        if action == "closed":
            with self.db.transaction() as db:
                db.execute(
                    "UPDATE github_pr_bindings SET is_stale = 1, commit_status = 'closed', updated_at = ? WHERE repo_full_name = ? AND pr_number = ?",
                    (_utc_now(), repo_full_name, pr_number),
                )
            return {
                "status": "pr_closed",
                "repo": repo_full_name,
                "pr_number": pr_number,
                "action": action,
            }

        # 7. Supported Actions for Verification: opened, synchronize, reopened
        if action not in ("opened", "synchronize", "reopened"):
            return {
                "status": "ignored_action",
                "repo": repo_full_name,
                "pr_number": pr_number,
                "action": action,
            }

        # 8. Detect & Invalidate Stale Prior Commits on PR Update (synchronize)
        with self.db.transaction() as db:
            prior_bindings = db.execute(
                "SELECT * FROM github_pr_bindings WHERE repo_full_name = ? AND pr_number = ? AND is_stale = 0",
                (repo_full_name, pr_number),
            ).fetchall()
            for prior in prior_bindings:
                if prior["head_sha"] != head_sha:
                    db.execute(
                        "UPDATE github_pr_bindings SET is_stale = 1, commit_status = 'superseded', updated_at = ? WHERE id = ?",
                        (_utc_now(), prior["id"]),
                    )
                    # Publish superseded status to previous commit
                    self.client.post_commit_status(
                        repo=repo_full_name,
                        sha=prior["head_sha"],
                        state="error",
                        description=f"SENTINEL-X: Superseded by new commit {head_sha[:8]}",
                        target_url=prior["status_target_url"],
                    )

        # 9. Retrieve and Validate Patch Diff (Authenticated & Bounded)
        diff_text = custom_diff or pr_data.get("diff_text")
        if not diff_text:
            diff_text = self.client.fetch_pull_request_diff(repo_full_name, pr_number)

        if not diff_text:
            raise WorkflowError(
                "No patch diff could be retrieved for this pull request",
                422,
                "EMPTY_DIFF",
            )

        if len(diff_text.encode("utf-8")) > self.settings.max_patch_bytes:
            raise WorkflowError(
                f"Patch diff exceeds maximum allowed limit ({self.settings.max_patch_bytes} bytes)",
                413,
                "PATCH_TOO_LARGE",
            )

        # Validate syntax, line endings, markers, and operations
        files_changed, additions, deletions = parse_and_validate_unified_diff(diff_text)
        auth_hash = patch_hash(diff_text)

        # 10. Check Target Source Revision
        target_app = "bola-demo-v1"
        source_root = self.workflow._source_root(None)
        authoritative_source_rev = TARGET_MANIFEST.source_revision(
            source_root, self.settings.protected_tests_root
        )

        # Validate Policy
        policy_reasons: List[str] = []
        policy_passed = True
        try:
            b_policy = validate_patch(
                target_app, diff_text, files_changed, attempt=1, settings=self.settings
            )
            if not b_policy.allowed:
                policy_passed = False
                policy_reasons.extend(b_policy.reasons)
        except Exception as e:
            policy_passed = False
            policy_reasons.append(str(e))

        try:
            PatchValidator.validate_patch(diff_text, expected_hash=auth_hash)
        except PatchValidationError as pve:
            policy_passed = False
            policy_reasons.append(str(pve))

        clean_reasons = list(dict.fromkeys(policy_reasons))
        policy_status = "PASSED" if policy_passed else "REJECTED"
        initial_status = (
            Status.AWAITING_APPROVAL.value if policy_passed else Status.POLICY_REJECTED.value
        )

        # 11. Create Real SENTINEL-X Verification Job
        job_id = _id("job")
        patch_id = _id("patch")
        binding_id = _id("gpr")
        candidate_id = _id("cand")
        now = _utc_now()
        evidence_url = f"{self.settings.sentinel_base_url}/evidence?jobId={job_id}"

        finding_dict = {
            "id": f"PR-{pr_number}-AUDIT",
            "type": "BROKEN_OBJECT_LEVEL_AUTHORIZATION",
            "severity": "HIGH",
            "file_path": files_changed[0] if files_changed else "app/access.py",
            "description": f"GitHub PR #{pr_number} security verification candidate (commit {head_sha[:8]})",
        }

        with self.db.transaction() as db:
            db.execute("""
                INSERT INTO jobs (id, target_app_id, finding_json, status, attempt, created_at, updated_at)
                VALUES (?, ?, ?, ?, 1, ?, ?)
            """, (job_id, target_app, json.dumps(finding_dict), initial_status, now, now))

            db.execute("""
                INSERT INTO job_bindings (job_id, source_revision, verification_profile)
                VALUES (?, ?, ?)
            """, (job_id, authoritative_source_rev, "bola-protected-tests-v1"))

            db.execute("""
                INSERT INTO patch_proposals (
                    id, job_id, attempt, root_cause, explanation, patch_format,
                    patch_text, files_changed_json, patch_hash, policy_status,
                    policy_details_json, created_at, authoring_source
                ) VALUES (?, ?, 1, ?, ?, 'unified_diff', ?, ?, ?, ?, ?, ?, ?)
            """, (
                patch_id,
                job_id,
                f"Candidate commit from GitHub PR #{pr_number}",
                f"Submitted via GitHub Pull Request #{pr_number} (Head: {head_sha[:10]})",
                diff_text,
                json.dumps(files_changed),
                auth_hash,
                policy_status,
                json.dumps({"reasons": clean_reasons}),
                now,
                f"GitHub PR #{pr_number} ({repo_full_name})",
            ))

            db.execute("""
                INSERT INTO candidate_patches (
                    id, job_id, project_id, finding_id, authoring_source,
                    patch_format, patch_hash, source_revision, policy_status, created_at
                ) VALUES (?, ?, ?, ?, ?, 'unified_diff', ?, ?, ?, ?)
            """, (
                candidate_id,
                job_id,
                None,
                finding_dict["id"],
                f"GitHub PR #{pr_number}",
                auth_hash,
                authoritative_source_rev,
                policy_status,
                now,
            ))

            # Store the GitHub PR binding
            commit_status = "pending" if policy_passed else "failure"
            db.execute("""
                INSERT INTO github_pr_bindings (
                    id, job_id, repo_full_name, pr_number, base_sha, head_sha,
                    patch_hash, commit_status, status_target_url, is_stale, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
            """, (
                binding_id,
                job_id,
                repo_full_name,
                pr_number,
                base_sha,
                head_sha,
                auth_hash,
                commit_status,
                evidence_url,
                now,
                now,
            ))

        # 12. Publish Commit Status to GitHub (Awaiting Approval or Policy Rejected)
        if policy_passed:
            initial_desc = "SENTINEL-X: Awaiting Human Approval"
            self.client.post_commit_status(
                repo=repo_full_name,
                sha=head_sha,
                state="pending",
                description=initial_desc,
                target_url=evidence_url,
            )
        else:
            initial_desc = f"SENTINEL-X: Policy Rejected ({clean_reasons[0] if clean_reasons else 'Policy violation'})"
            self.client.post_commit_status(
                repo=repo_full_name,
                sha=head_sha,
                state="failure",
                description=initial_desc,
                target_url=evidence_url,
            )

        return {
            "status": "intake_complete",
            "binding_id": binding_id,
            "job_id": job_id,
            "repo": repo_full_name,
            "pr_number": pr_number,
            "base_sha": base_sha,
            "head_sha": head_sha,
            "patch_hash": auth_hash,
            "policy_status": policy_status,
            "evidence_url": evidence_url,
        }

    def sync_job_status_to_github(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Synchronizes current verification status for a job to GitHub commit status."""
        with self.db.read() as db:
            binding = db.execute(
                "SELECT * FROM github_pr_bindings WHERE job_id = ?",
                (job_id,),
            ).fetchone()
            if not binding:
                return None

            job = db.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            latest_run = db.execute(
                "SELECT * FROM verification_runs WHERE job_id = ? ORDER BY created_at DESC LIMIT 1",
                (job_id,),
            ).fetchone()

        # Check if stale - do not post success for stale commits!
        if binding["is_stale"] == 1:
            logger.info("Commit %s is marked stale; skipping positive result publication", binding["head_sha"])
            return {"status": "superseded_ignored", "head_sha": binding["head_sha"]}

        job_status = job["status"]
        state = "pending"
        desc = "SENTINEL-X verification in progress"

        if latest_run and latest_run["status"] == Status.VERIFICATION_FAILED.value:
            state = "failure"
            desc = "SENTINEL-X: Verification FAILED (Security defects detected)"
        elif latest_run and latest_run["status"] == Status.VERIFIED.value:
            state = "success"
            desc = "SENTINEL-X: Verification PASSED (All tests passed)"
        elif latest_run and latest_run["status"] == Status.EXECUTION_ERROR.value:
            state = "error"
            desc = "SENTINEL-X: Verification container execution error"
        elif job_status == Status.AWAITING_APPROVAL.value:
            state = "pending"
            desc = "SENTINEL-X: Awaiting Human Approval"
        elif job_status == Status.VERIFYING.value:
            state = "pending"
            desc = "SENTINEL-X: Verifying in isolated container..."
        elif job_status == Status.VERIFIED.value:
            state = "success"
            desc = "SENTINEL-X: Verification PASSED (All tests passed)"
        elif job_status == Status.VERIFICATION_FAILED.value:
            state = "failure"
            desc = "SENTINEL-X: Verification FAILED (Security defects detected)"
        elif job_status == Status.POLICY_REJECTED.value:
            state = "failure"
            desc = "SENTINEL-X: Policy rejected candidate patch"
        elif job_status == Status.USER_REJECTED.value:
            state = "failure"
            desc = "SENTINEL-X: Operator rejected candidate patch"
        elif job_status == Status.EXECUTION_ERROR.value:
            state = "error"
            desc = "SENTINEL-X: Verification container execution error"

        res = self.client.post_commit_status(
            repo=binding["repo_full_name"],
            sha=binding["head_sha"],
            state=state,
            description=desc,
            target_url=binding["status_target_url"],
        )

        with self.db.transaction() as db:
            db.execute(
                "UPDATE github_pr_bindings SET commit_status = ?, updated_at = ? WHERE id = ?",
                (state, _utc_now(), binding["id"]),
            )

        return {"published_state": state, "description": desc, "github_response": res}
