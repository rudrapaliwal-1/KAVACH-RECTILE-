"""Tests for AI-Agnostic Patch Intake and Comparison Lab."""

import pytest
from backend.policy import patch_hash
from backend.schemas import PatchIntakeRequest


VALID_DIFF_CLAUDE = """diff --git a/app/access.py b/app/access.py
--- a/app/access.py
+++ b/app/access.py
@@ -1 +1 @@
-return document
+return document if owner == user else None  # fix by Claude 3.7
"""

VALID_DIFF_CURSOR = """diff --git a/app/access.py b/app/access.py
--- a/app/access.py
+++ b/app/access.py
@@ -1 +1,2 @@
-return document
+if not is_document_owner(user, document): return None
+return document  # fix by Cursor
"""

VALID_DIFF_MANUAL = """diff --git a/app/access.py b/app/access.py
--- a/app/access.py
+++ b/app/access.py
@@ -1 +1 @@
-return document
+return check_authorization_and_return(document, user)  # manual fix
"""

BROKEN_DIFF_INSUFFICIENT = """diff --git a/app/access.py b/app/access.py
--- a/app/access.py
+++ b/app/access.py
@@ -1 +1 @@
-return document
+return document  # bypass attempt claiming to be Claude
"""


def test_patch_intake_from_different_authoring_sources(setup, operator_headers):
    client, _, _, _ = setup

    sources = [
        ("Claude 3.7 Sonnet", VALID_DIFF_CLAUDE),
        ("Cursor / Claude-3.5", VALID_DIFF_CURSOR),
        ("Manual Developer", VALID_DIFF_MANUAL),
    ]

    candidate_job_ids = []
    for source_label, diff_text in sources:
        response = client.post(
            "/api/patches/intake",
            headers=operator_headers,
            json={
                "target_app_id": "bola-demo-v1",
                "finding_id": "BOLA-001",
                "patch_text": diff_text,
                "authoring_source": source_label,
            },
        )
        assert response.status_code == 200, response.text
        data = response.json()
        assert data["job_id"].startswith("job-")
        assert data["candidate_id"].startswith("cand-")
        assert data["authoring_source"] == source_label
        assert data["policy_status"] == "PASSED"
        assert data["status"] == "AWAITING_APPROVAL"
        assert data["patch_hash"] == patch_hash(diff_text)
        candidate_job_ids.append(data["job_id"])

    # Verify each candidate exists independently in the database
    for jid in candidate_job_ids:
        job = client.get(f"/api/jobs/{jid}").json()
        assert job["status"] == "AWAITING_APPROVAL"
        patch = client.get(f"/api/jobs/{jid}/patch").json()
        assert patch["policy_status"] == "PASSED"


def test_behavior_over_claimed_origin_and_adversarial_outcome(setup, operator_headers):
    """Demonstrates that SENTINEL-X evaluates candidate patches according to actual behavior,

    not their claimed model origin or prestige.
    """
    client, _, verifier, _ = setup

    # Candidate A: Valid fix claiming to be Claude
    res_a = client.post(
        "/api/patches/intake",
        headers=operator_headers,
        json={
            "target_app_id": "bola-demo-v1",
            "finding_id": "BOLA-001",
            "patch_text": VALID_DIFF_CLAUDE,
            "authoring_source": "Claude 3.7 Sonnet",
        },
    )
    assert res_a.status_code == 200
    job_a = res_a.json()["job_id"]
    hash_a = res_a.json()["patch_hash"]

    # Candidate B: Broken/inadequate fix ALSO claiming to be Claude 3.7 Sonnet
    res_b = client.post(
        "/api/patches/intake",
        headers=operator_headers,
        json={
            "target_app_id": "bola-demo-v1",
            "finding_id": "BOLA-001",
            "patch_text": BROKEN_DIFF_INSUFFICIENT,
            "authoring_source": "Claude 3.7 Sonnet",
        },
    )
    assert res_b.status_code == 200
    job_b = res_b.json()["job_id"]
    hash_b = res_b.json()["patch_hash"]

    # Configure verifier: first run passes, second run fails
    verifier.statuses = ["PASSED", "FAILED"]

    # Approve both candidates with their exact hashes
    app_a = client.post(f"/api/jobs/{job_a}/approval", headers=operator_headers,
                        json={"patch_hash": hash_a, "decision": "APPROVE"})
    assert app_a.status_code == 200

    app_b = client.post(f"/api/jobs/{job_b}/approval", headers=operator_headers,
                        json={"patch_hash": hash_b, "decision": "APPROVE"})
    assert app_b.status_code == 200

    # Verify Candidate A: passes
    ver_a = client.post(f"/api/jobs/{job_a}/verify", headers=operator_headers)
    assert ver_a.status_code == 200
    assert ver_a.json()["status"] == "VERIFIED"

    # Verify Candidate B: fails despite claiming to be Claude 3.7!
    ver_b = client.post(f"/api/jobs/{job_b}/verify", headers=operator_headers)
    assert ver_b.status_code == 200
    assert ver_b.json()["status"] == "VERIFICATION_FAILED"


def test_client_supplied_patch_hash_is_never_trusted(setup, operator_headers):
    client, _, _, _ = setup
    spoofed_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

    response = client.post(
        "/api/patches/intake",
        headers=operator_headers,
        json={
            "target_app_id": "bola-demo-v1",
            "finding_id": "BOLA-001",
            "patch_text": VALID_DIFF_CLAUDE,
            "authoring_source": "Adversarial Model",
            "claimed_patch_hash": spoofed_hash,
        },
    )
    assert response.status_code == 200
    data = response.json()
    # Backend must recompute authoritative hash and ignore spoofed hash
    assert data["patch_hash"] != spoofed_hash
    assert data["patch_hash"] == patch_hash(VALID_DIFF_CLAUDE)


def test_intake_rejects_malformed_diffs(setup, operator_headers):
    client, _, _, _ = setup

    # Case 1: Plain text without diff header
    res1 = client.post(
        "/api/patches/intake",
        headers=operator_headers,
        json={"target_app_id": "bola-demo-v1", "patch_text": "Just check if user is owner.\n"},
    )
    assert res1.status_code == 422
    assert "NON_UNIFIED_DIFF" in res1.text or "MALFORMED_DIFF" in res1.text

    # Case 2: Hunk line count mismatch
    bad_hunk_diff = """diff --git a/app/access.py b/app/access.py
--- a/app/access.py
+++ b/app/access.py
@@ -1,99 +1,99 @@
-return document
+return document if owner else None
"""
    res2 = client.post(
        "/api/patches/intake",
        headers=operator_headers,
        json={"target_app_id": "bola-demo-v1", "patch_text": bad_hunk_diff},
    )
    assert res2.status_code == 200  # Stored with policy rejection
    assert res2.json()["policy_status"] == "REJECTED"
    assert res2.json()["status"] == "POLICY_REJECTED"
    assert any("mismatch" in r.lower() for r in res2.json()["policy_reasons"])


def test_intake_rejects_unauthorized_and_protected_file_changes(setup, operator_headers):
    client, _, _, _ = setup

    # Attempt to modify protected test suite
    protected_diff = """diff --git a/verification/protected_tests/test_bola.py b/verification/protected_tests/test_bola.py
--- a/verification/protected_tests/test_bola.py
+++ b/verification/protected_tests/test_bola.py
@@ -1 +1 @@
-assert False
+assert True
"""
    res = client.post(
        "/api/patches/intake",
        headers=operator_headers,
        json={"target_app_id": "bola-demo-v1", "patch_text": protected_diff},
    )
    assert res.status_code == 200
    assert res.json()["policy_status"] == "REJECTED"
    assert res.json()["status"] == "POLICY_REJECTED"


def test_intake_rejects_stale_source_revision(setup, operator_headers):
    client, _, _, _ = setup
    stale_rev = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

    res = client.post(
        "/api/patches/intake",
        headers=operator_headers,
        json={
            "target_app_id": "bola-demo-v1",
            "patch_text": VALID_DIFF_CLAUDE,
            "claimed_source_revision": stale_rev,
        },
    )
    assert res.status_code == 409
    assert "STALE_SOURCE_REVISION" in res.text


def test_all_external_sources_require_human_approval(setup, operator_headers):
    client, _, _, _ = setup

    # Intake from prestigious AI tool
    res = client.post(
        "/api/patches/intake",
        headers=operator_headers,
        json={
            "target_app_id": "bola-demo-v1",
            "patch_text": VALID_DIFF_CLAUDE,
            "authoring_source": "OpenAI o3-mini",
        },
    )
    assert res.status_code == 200
    job_id = res.json()["job_id"]

    # Verification must be blocked before approval
    verify_res = client.post(f"/api/jobs/{job_id}/verify", headers=operator_headers)
    assert verify_res.status_code == 409
    assert "not ready for verification" in verify_res.text.lower() or "unapproved" in verify_res.text.lower()


def test_rejected_approval_prevents_verification(setup, operator_headers):
    client, _, _, _ = setup

    res = client.post(
        "/api/patches/intake",
        headers=operator_headers,
        json={"target_app_id": "bola-demo-v1", "patch_text": VALID_DIFF_CLAUDE},
    )
    job_id = res.json()["job_id"]
    p_hash = res.json()["patch_hash"]

    # Reject approval
    rej = client.post(f"/api/jobs/{job_id}/approval", headers=operator_headers,
                      json={"patch_hash": p_hash, "decision": "REJECT"})
    assert rej.status_code == 200

    # Verification must fail
    ver = client.post(f"/api/jobs/{job_id}/verify", headers=operator_headers)
    assert ver.status_code == 409


def test_unsupported_patch_formats_rejected(setup, operator_headers):
    client, _, _, _ = setup

    # 1. Binary patch
    binary_diff = "diff --git a/file b/file\nGIT binary patch\nliteral 0\n"
    res1 = client.post("/api/patches/intake", headers=operator_headers,
                       json={"target_app_id": "bola-demo-v1", "patch_text": binary_diff})
    assert res1.status_code == 422
    assert "binary" in res1.text.lower() or "prohibited" in res1.text.lower()

    # 2. Windows CRLF
    crlf_diff = "diff --git a/app/access.py b/app/access.py\r\n--- a/app/access.py\r\n+++ b/app/access.py\r\n"
    res2 = client.post("/api/patches/intake", headers=operator_headers,
                       json={"target_app_id": "bola-demo-v1", "patch_text": crlf_diff})
    assert res2.status_code == 422
    assert "CRLF" in res2.text or "UNSUPPORTED_PATCH_ENCODING" in res2.text

    # 3. Rename operation
    rename_diff = """diff --git a/app/access.py b/app/other.py
rename from app/access.py
rename to app/other.py
"""
    res3 = client.post("/api/patches/intake", headers=operator_headers,
                       json={"target_app_id": "bola-demo-v1", "patch_text": rename_diff})
    assert res3.status_code == 422
    assert "rename" in res3.text.lower() or "PROHIBITED" in res3.text


def test_patch_comparison_normalizes_and_detects_discrepancies(setup, operator_headers):
    client, _, verifier, _ = setup

    # Submit Candidate 1
    c1 = client.post("/api/patches/intake", headers=operator_headers,
                     json={"target_app_id": "bola-demo-v1", "patch_text": VALID_DIFF_CLAUDE,
                           "authoring_source": "Claude 3.7"}).json()
    # Submit Candidate 2
    c2 = client.post("/api/patches/intake", headers=operator_headers,
                     json={"target_app_id": "bola-demo-v1", "patch_text": VALID_DIFF_CURSOR,
                           "authoring_source": "Cursor"}).json()

    # Approve and verify Candidate 1
    client.post(f"/api/jobs/{c1['job_id']}/approval", headers=operator_headers,
                json={"patch_hash": c1["patch_hash"], "decision": "APPROVE"})
    client.post(f"/api/jobs/{c1['job_id']}/verify", headers=operator_headers)

    # Compare candidates
    comp_res = client.get(f"/api/candidates/compare?job_ids={c1['job_id']},{c2['job_id']}")
    assert comp_res.status_code == 200
    report = comp_res.json()

    assert len(report["candidates"]) == 2
    assert report["source_revision_mismatch"] is False
    assert report["test_suite_discrepancy"] is False
    assert any("Normalized" in n for n in report["fair_comparison_notes"])
    # Disclaimer explicitly confirms no arbitrary composite score
    assert "composite score" in report["disclaimer"]

    # Verify Candidate 1 reflects verified results
    cand1 = next(c for c in report["candidates"] if c["job_id"] == c1["job_id"])
    assert cand1["status"] == "VERIFIED"
    assert cand1["approval_status"] == "APPROVED"
    assert cand1["tests_passed"] == 2

    # Verify Candidate 2 reflects pending approval
    cand2 = next(c for c in report["candidates"] if c["job_id"] == c2["job_id"])
    assert cand2["status"] == "AWAITING_APPROVAL"
    assert cand2["approval_status"] == "PENDING_APPROVAL"
    assert cand2["tests_passed"] is None


def test_candidate_results_never_cross_contaminate(setup, operator_headers):
    client, _, verifier, _ = setup

    c1 = client.post("/api/patches/intake", headers=operator_headers,
                     json={"target_app_id": "bola-demo-v1", "patch_text": VALID_DIFF_CLAUDE,
                           "authoring_source": "Claude"}).json()
    c2 = client.post("/api/patches/intake", headers=operator_headers,
                     json={"target_app_id": "bola-demo-v1", "patch_text": VALID_DIFF_CURSOR,
                           "authoring_source": "Cursor"}).json()

    # Approve & verify ONLY candidate 1
    client.post(f"/api/jobs/{c1['job_id']}/approval", headers=operator_headers,
                json={"patch_hash": c1["patch_hash"], "decision": "APPROVE"})
    client.post(f"/api/jobs/{c1['job_id']}/verify", headers=operator_headers)

    # Candidate 2's evidence must NOT contain candidate 1's results
    ev2 = client.get(f"/api/jobs/{c2['job_id']}/evidence").json()
    assert len(ev2.get("verification_runs", [])) == 0
    assert len(ev2.get("approvals", [])) == 0
    assert ev2.get("conclusion") is None or ev2.get("conclusion") != "VERIFIED"


def test_duplicate_intake_requests_create_distinct_trackable_candidates(setup, operator_headers):
    client, _, _, _ = setup

    # Submit identical diff twice
    res1 = client.post("/api/patches/intake", headers=operator_headers,
                       json={"target_app_id": "bola-demo-v1", "patch_text": VALID_DIFF_CLAUDE,
                             "authoring_source": "Claude 3.7 (Run 1)"})
    res2 = client.post("/api/patches/intake", headers=operator_headers,
                       json={"target_app_id": "bola-demo-v1", "patch_text": VALID_DIFF_CLAUDE,
                             "authoring_source": "Claude 3.7 (Run 2)"})

    assert res1.status_code == 200
    assert res2.status_code == 200

    job1 = res1.json()["job_id"]
    job2 = res2.json()["job_id"]

    # Must produce separate, distinct trackable jobs and candidates
    assert job1 != job2
    assert res1.json()["candidate_id"] != res2.json()["candidate_id"]
    assert res1.json()["patch_hash"] == res2.json()["patch_hash"]
