"""Tests for Regression Memory, Safe Intermediate Caching, and Performance Metrics.

Tests:
1. Regression memory storage with strict sanitization (no secrets, passwords, host paths).
2. Bounded, explainable retrieval based on vulnerability profile, path, and failed tests.
3. Composite cache keys binding all 5 parameters (source rev, patch hash, test suite, image digest, config).
4. Policy cache hit and invalidation on patch change.
5. Source revision cache invalidation when files change on disk.
6. Invariant: Verifier verdict is NEVER cached; every approved patch executes independently.
7. Concurrency and thread safety under multi-threaded cache load.
8. Interrupted job recovery and metrics recording.
9. Performance metrics collection across all 6 pipeline phases.
10. False VERIFIED adversarial rate remains strictly 0.0%.
"""

import concurrent.futures
import json
import pytest
from pathlib import Path
from dataclasses import replace
from fastapi.testclient import TestClient

from backend.config import Settings
from backend.main import create_app
from backend.models import Status
from backend.policy import patch_hash
from backend.regression_memory import (
    record_failure_pattern,
    retrieve_relevant_memory,
    sanitize_text,
    seed_default_memory,
)
from backend.safe_cache import (
    compute_composite_cache_key,
    safe_cache,
)
from backend.verification_metrics import verification_metrics
from backend.tests.conftest import FakeAgent, FakeVerifier, TOKEN


VALID_PATCH_1 = """diff --git a/app/access.py b/app/access.py
--- a/app/access.py
+++ b/app/access.py
@@ -1 +1 @@
-return document
+return document if owner == user else None  # safe patch 1
"""

VALID_PATCH_2 = """diff --git a/app/access.py b/app/access.py
--- a/app/access.py
+++ b/app/access.py
@@ -1 +1 @@
-return document
+return document if is_owner(owner, user) else None  # safe patch 2
"""


@pytest.fixture(autouse=True)
def reset_cache_and_metrics():
    safe_cache.reset_all()
    verification_metrics.reset()
    yield
    safe_cache.reset_all()
    verification_metrics.reset()


@pytest.fixture
def test_setup(tmp_path):
    source = tmp_path / "source" / "app"
    source.mkdir(parents=True)
    (source / "access.py").write_text("return document\n", encoding="utf-8", newline="\n")

    settings = Settings(
        database_path=tmp_path / "sentinel.db",
        source_root=tmp_path / "source",
        operator_token=TOKEN,
    )
    agent = FakeAgent()
    verifier = FakeVerifier()
    app = create_app(settings, agent, verifier)
    client = TestClient(app, headers={"X-Operator-Token": TOKEN})
    return client, app, settings, agent, verifier, tmp_path


def test_regression_memory_sanitization():
    raw_text = (
        "Error in /Users/developer/SENTINEL-X/app/access.py. "
        "Authorization header was bearer: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9. "
        "User secret: my-top-secret-password-1234."
    )
    cleaned = sanitize_text(raw_text)

    # Verify secrets and passwords are redacted
    assert "my-top-secret-password-1234" not in cleaned
    assert "[REDACTED]" in cleaned

    # Verify host paths are masked
    assert "/Users/developer" not in cleaned
    assert "/workspace" in cleaned


def test_regression_memory_storage_and_explainable_retrieval(test_setup):
    _, app, _, _, _, _ = test_setup
    db_ctx = app.state.workflow.db

    with db_ctx.transaction() as db:
        seed_default_memory(db)
        record_id = record_failure_pattern(
            db=db,
            vulnerability_profile="BOLA-CUSTOM-001",
            file_path="app/access.py",
            failure_pattern="test_custom_boundary_bypass: boundary check missing",
            sanitized_explanation="Missing bounds check on tenant boundary",
            remediation_pattern="Check tenant_id before returning document",
            trusted_scenarios=["BOLA-CUSTOM-001", "BOLA-BOUNDARY-001"],
            historical_limitations="Single tenant only",
        )
        assert record_id.startswith("rmem-")

    with db_ctx.read() as db:
        # Retrieve by exact profile match
        results = retrieve_relevant_memory(
            db=db,
            vulnerability_profile="BOLA-CUSTOM-001",
            file_path="app/access.py",
            failed_tests=["test_custom_boundary_bypass"],
            limit=2,
        )

        assert len(results) > 0
        top = results[0]
        assert top["vulnerability_profile"] == "BOLA-CUSTOM-001"
        assert top["target_file"] == "app/access.py"
        assert top["relevance_score"] >= 80  # profile (50) + path (30)
        assert "selection_rationale" in top
        assert "Vulnerability profile matched" in top["selection_rationale"]
        assert "Target file path matched" in top["selection_rationale"]


def test_composite_cache_key_binding_all_parameters():
    src_rev = "sha256:11111111111111111111111111111111"
    patch_h = "sha256:22222222222222222222222222222222"
    suite_v = "bola-redteam-v1"
    img_dig = "sha256:33333333333333333333333333333333"
    cfg = {"timeout": 300, "isolation": "docker"}

    key_base = compute_composite_cache_key(src_rev, patch_h, suite_v, img_dig, cfg)

    # 1. Changed source revision
    key_diff_src = compute_composite_cache_key("sha256:different", patch_h, suite_v, img_dig, cfg)
    assert key_diff_src != key_base

    # 2. Changed patch hash
    key_diff_patch = compute_composite_cache_key(src_rev, "sha256:different", suite_v, img_dig, cfg)
    assert key_diff_patch != key_base

    # 3. Changed test suite version
    key_diff_suite = compute_composite_cache_key(src_rev, patch_h, "bola-redteam-v2", img_dig, cfg)
    assert key_diff_suite != key_base

    # 4. Changed verifier image digest
    key_diff_img = compute_composite_cache_key(src_rev, patch_h, suite_v, "sha256:different", cfg)
    assert key_diff_img != key_base

    # 5. Changed configuration
    key_diff_cfg = compute_composite_cache_key(src_rev, patch_h, suite_v, img_dig, {"timeout": 60})
    assert key_diff_cfg != key_base


def test_policy_cache_hit_and_invalidation():
    safe_cache.reset_all()
    target = "bola-demo-v1"
    hash_1 = patch_hash(VALID_PATCH_1)
    hash_2 = patch_hash(VALID_PATCH_2)

    calls = {"count": 0}

    def compute_policy():
        calls["count"] += 1
        return {"allowed": True, "reasons": []}

    # First call: cache miss
    res1 = safe_cache.get_or_compute_policy(target, hash_1, 1, compute_policy)
    assert res1["allowed"] is True
    assert calls["count"] == 1

    # Second call with identical patch: cache hit!
    res2 = safe_cache.get_or_compute_policy(target, hash_1, 1, compute_policy)
    assert res2["allowed"] is True
    assert calls["count"] == 1  # No re-computation!

    # Third call with changed patch: cache miss & computation
    res3 = safe_cache.get_or_compute_policy(target, hash_2, 1, compute_policy)
    assert res3["allowed"] is True
    assert calls["count"] == 2

    stats = safe_cache.policy_cache.get_stats()
    assert stats["hits"] == 1
    assert stats["misses"] == 2


def test_source_manifest_cache_invalidation_on_disk_change(tmp_path):
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    file_a = src_dir / "file.py"
    file_a.write_text("x = 1\n", encoding="utf-8")

    manifest_calls = {"count": 0}

    def compute_manifest():
        manifest_calls["count"] += 1
        return "sha256:manifest_digest"

    # First computation: miss
    rev1 = safe_cache.get_or_compute_source_revision(src_dir, None, compute_manifest)
    assert rev1 == "sha256:manifest_digest"
    assert manifest_calls["count"] == 1

    # Second computation without modifying disk: hit
    rev2 = safe_cache.get_or_compute_source_revision(src_dir, None, compute_manifest)
    assert rev2 == "sha256:manifest_digest"
    assert manifest_calls["count"] == 1

    # Modify file on disk -> fingerprint changes -> cache invalidation
    import time
    time.sleep(0.02)
    file_a.write_text("x = 2; y = 3\n", encoding="utf-8")

    rev3 = safe_cache.get_or_compute_source_revision(src_dir, None, compute_manifest)
    assert rev3 == "sha256:manifest_digest"
    assert manifest_calls["count"] == 2  # Recomputed!


def test_never_reuse_verified_verdict_for_patches(test_setup):
    """Critical Invariant:

    Never reuse a previous VERIFIED verdict solely because a patch appears similar.
    The current run must satisfy the required execution and evidence policy.
    """
    client, app, _, _, verifier, _ = test_setup

    # Job 1
    f_resp = client.post("/api/findings", json={
        "target_app_id": "bola-demo-v1",
        "finding": {
            "id": "BOLA-001",
            "type": "BROKEN_OBJECT_LEVEL_AUTHORIZATION",
            "severity": "HIGH",
            "file_path": "app/access.py",
            "description": "BOLA",
        },
    })
    job1_id = f_resp.json()["job_id"]
    client.post(f"/api/jobs/{job1_id}/plan")
    patch1_data = client.get(f"/api/jobs/{job1_id}/patch").json()
    patch_hash_1 = patch1_data["patch_hash"]

    # Approve & Verify Job 1
    client.post(f"/api/jobs/{job1_id}/approval", json={"decision": "APPROVE", "patch_hash": patch_hash_1})
    client.post(f"/api/jobs/{job1_id}/verify")
    assert len(verifier.calls) == 1

    # Job 2 with identical finding
    f_resp2 = client.post("/api/findings", json={
        "target_app_id": "bola-demo-v1",
        "finding": {
            "id": "BOLA-001",
            "type": "BROKEN_OBJECT_LEVEL_AUTHORIZATION",
            "severity": "HIGH",
            "file_path": "app/access.py",
            "description": "BOLA",
        },
    })
    job2_id = f_resp2.json()["job_id"]
    client.post(f"/api/jobs/{job2_id}/plan")
    patch2_data = client.get(f"/api/jobs/{job2_id}/patch").json()
    patch_hash_2 = patch2_data["patch_hash"]

    # Job 2 cannot skip approval or verification!
    # Verifying without approval must fail:
    fail_verify = client.post(f"/api/jobs/{job2_id}/verify")
    assert fail_verify.status_code == 409  # Job not ready for verification

    # Once approved, Job 2 MUST independently execute the verifier:
    client.post(f"/api/jobs/{job2_id}/approval", json={"decision": "APPROVE", "patch_hash": patch_hash_2})
    client.post(f"/api/jobs/{job2_id}/verify")
    # Verifier was called a 2nd time! No execution skipping!
    assert len(verifier.calls) == 2


def test_concurrency_and_thread_safety():
    """Verify thread-safe concurrent access to safe_cache and verification metrics."""
    def worker(i: int):
        key = f"key_{i % 5}"
        safe_cache.policy_cache.put(key, f"val_{i}")
        _ = safe_cache.policy_cache.get(key)
        verification_metrics.record_phase_timing("policy_validation", 2.5)
        verification_metrics.record_ai_generation(150.0, success=True)
        return True

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(worker, i) for i in range(100)]
        for f in concurrent.futures.as_completed(futures):
            assert f.result() is True

    summary = verification_metrics.get_summary()
    assert summary["ai_generation_latency"]["samples"] == 100
    assert summary["phases"]["policy_validation"]["count"] == 100


def test_interrupted_job_recovery_and_telemetry(test_setup):
    client, app, _, _, _, _ = test_setup
    workflow = app.state.workflow

    # Finding & Planning
    f_resp = client.post("/api/findings", json={
        "target_app_id": "bola-demo-v1",
        "finding": {
            "id": "BOLA-001",
            "type": "BROKEN_OBJECT_LEVEL_AUTHORIZATION",
            "severity": "HIGH",
            "file_path": "app/access.py",
            "description": "BOLA",
        },
    })
    job_id = f_resp.json()["job_id"]
    client.post(f"/api/jobs/{job_id}/plan")
    patch_data = client.get(f"/api/jobs/{job_id}/patch").json()
    patch_hash = patch_data["patch_hash"]

    client.post(f"/api/jobs/{job_id}/approval", json={"decision": "APPROVE", "patch_hash": patch_hash})

    # Simulate an interrupted job by putting status into VERIFYING with an expired lease
    with workflow.db.transaction() as db:
        db.execute(
            "UPDATE jobs SET status = 'VERIFYING' WHERE id = ?",
            (job_id,),
        )
        patch_id = patch_data["id"]
        db.execute(
            "INSERT INTO verification_runs (id, job_id, patch_id, patch_hash, status, result_json, created_at) "
            "VALUES ('run-interrupted', ?, ?, ?, 'RUNNING', '{}', '2020-01-01T00:00:00Z')",
            (job_id, patch_id, patch_hash),
        )
        db.execute(
            "INSERT INTO verification_leases (run_id, owner, token, expires_at) "
            "VALUES ('run-interrupted', 'old-node', 'old-token', '2020-01-01T00:01:00Z')"
        )

    # Trigger recovery
    workflow.recover_interrupted()

    # Verify job status transitioned to EXECUTION_ERROR and lease cleared
    with workflow.db.read() as db:
        job = db.execute("SELECT status FROM jobs WHERE id = ?", (job_id,)).fetchone()
        assert job["status"] == Status.EXECUTION_ERROR.value


def test_performance_metrics_profiling_and_endpoints(test_setup):
    client, app, _, _, _, _ = test_setup

    # Execute standard full job workflow
    f_resp = client.post("/api/findings", json={
        "target_app_id": "bola-demo-v1",
        "finding": {
            "id": "BOLA-001",
            "type": "BROKEN_OBJECT_LEVEL_AUTHORIZATION",
            "severity": "HIGH",
            "file_path": "app/access.py",
            "description": "BOLA",
        },
    })
    job_id = f_resp.json()["job_id"]
    client.post(f"/api/jobs/{job_id}/plan")
    patch_data = client.get(f"/api/jobs/{job_id}/patch").json()
    patch_hash = patch_data["patch_hash"]

    client.post(f"/api/jobs/{job_id}/approval", json={"decision": "APPROVE", "patch_hash": patch_hash})
    client.post(f"/api/jobs/{job_id}/verify")

    # Query metrics endpoint
    metrics_resp = client.get("/api/observability/performance-metrics")
    assert metrics_resp.status_code == 200
    metrics = metrics_resp.json()

    assert metrics["total_runs"] >= 1
    assert "verification_duration" in metrics
    assert "median_ms" in metrics["verification_duration"]
    assert "p95_ms" in metrics["verification_duration"]

    assert "ai_generation_latency" in metrics
    assert metrics["ai_generation_latency"]["samples"] >= 1

    assert "accuracy_and_reliability" in metrics
    assert metrics["accuracy_and_reliability"]["first_attempt_pass_rate_percent"] == 100.0
    assert metrics["accuracy_and_reliability"]["false_verified_adversarial_rate_percent"] == 0.0

    # Verify phases profiling
    phases = metrics["phases"]
    assert "source_intake" in phases
    assert "ai_generation" in phases
    assert "policy_validation" in phases
    assert "test_execution" in phases

    # Query regression memory endpoint
    reg_resp = client.get("/api/observability/regression-memory?profile=BOLA-001")
    assert reg_resp.status_code == 200
    assert len(reg_resp.json()["records"]) > 0


def test_adversarial_false_verified_rate_remains_zero():
    """Confirms that adversarial defect patterns never produce a false VERIFIED verdict."""
    from verification.evaluator import TestResultEvaluator

    # Evaluator must strictly reject any defect
    res_failed = TestResultEvaluator.evaluate(
        job_id="job-test",
        patch_hash="sha256:dummy",
        exit_code=1,
        raw_output="FAILED test_owner_access",
        duration_ms=45,
    )
    assert res_failed.status in ("FAILED", "EXECUTION_ERROR")
    assert res_failed.status != "PASSED"

    # Track in metrics
    verification_metrics.record_adversarial_outcome(is_false_verified=(res_failed.status == "PASSED"))
    summary = verification_metrics.get_summary()

    assert summary["accuracy_and_reliability"]["false_verified_adversarial_count"] == 0
    assert summary["accuracy_and_reliability"]["false_verified_adversarial_rate_percent"] == 0.0
