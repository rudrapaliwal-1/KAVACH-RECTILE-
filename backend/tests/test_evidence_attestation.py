"""Comprehensive Tampering & Integrity Verification Tests for Attestation Engine.

Demonstrates all required tamper-detection conditions:
1. Valid baseline attestation passes consistency and digital signature checks.
2. Changed patch bytes detected.
3. Changed source digest detected.
4. Altered test outcomes detected (reconciliation failure).
5. Missing individual tests detected (count mismatch).
6. Modified approval records detected.
7. Invalid or corrupted digital signatures detected.
8. Unsupported schema versions detected.
9. Evidence referring to the wrong verification run detected.
10. Cryptographic key rotation support.
11. Offline independent verification API.
12. Explicit documentation of attestation claims and limitations.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import pytest
from fastapi.testclient import TestClient

from backend.attestation import (
    AttestationEngine,
    AttestationIntegrityError,
    KeyRegistry,
    SENTINEL_ATTESTATION_SCHEMA_V1,
    canonical_json_bytes,
    compute_sha256,
)
from cryptography.hazmat.primitives.asymmetric import ed25519


@pytest.fixture
def sample_valid_payload():
    """Generates a complete, consistent attestation payload for testing."""
    tests_summary = {"total": 3, "passed": 3, "failed": 0, "exit_status": 0, "timed_out": False, "infrastructure_status": "HEALTHY"}
    test_results = [
        {"name": "test_owner_access", "outcome": "passed", "duration_ms": 2},
        {"name": "test_cross_user_denied", "outcome": "passed", "duration_ms": 3},
        {"name": "test_boundary_handling", "outcome": "passed", "duration_ms": 1},
    ]

    return AttestationEngine.create_attestation(
        run_id="run-valid-001",
        project_id="project-alpha-123",
        job_id="job-test-456",
        target_app_id="bola-demo-v1",
        source_revision="commit-abcdef123456",
        source_digest="sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        patch_hash="sha256:112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00",
        attempt=1,
        patch_id="patch-001",
        approved_by="operator@sentinel-x.local",
        approved_at="2026-10-20T19:00:00Z",
        approval_id="appr-001",
        test_suite_id="bola-required-tests-v1",
        test_suite_version="bola-redteam-v1",
        tests_summary=tests_summary,
        test_results=test_results,
        verdict="VERIFIED",
        sign=True,
    )


def test_valid_attestation_passes_validation(sample_valid_payload):
    """Verify that an untampered attestation passes consistency, digest, and digital signature checks."""
    result = AttestationEngine.verify_attestation(sample_valid_payload)
    assert result.valid is True
    assert result.signature_valid is True
    assert result.algorithm == "ed25519"
    assert result.key_id == "sentinel-key-2026-v1"
    assert len(result.issues) == 0
    assert result.reconciled_tests["total"] == 3
    assert result.reconciled_tests["passed"] == 3
    assert result.reconciled_tests["failed"] == 0


def test_tampered_patch_bytes_detected(sample_valid_payload):
    """Test 1: Changed patch bytes must be detected when compared against patch text."""
    genuine_patch_text = "--- a/app/access.py\n+++ b/app/access.py\n@@ -1 +1 @@\n+patched\n"
    tampered_patch_text = "--- a/app/access.py\n+++ b/app/access.py\n@@ -1 +1 @@\n+malicious_backdoor\n"

    # Set patch_hash to genuine patch
    sample_valid_payload["patch_hash"] = compute_sha256(genuine_patch_text)

    # Re-verify with tampered patch text
    result = AttestationEngine.verify_attestation(
        sample_valid_payload,
        patch_text=tampered_patch_text,
    )
    assert result.valid is False
    assert any("Patch hash mismatch" in issue for issue in result.issues)


def test_tampered_source_digest_detected(sample_valid_payload):
    """Test 2: Changed source digest must be detected when compared against actual source files."""
    genuine_source = b"def get_document(): pass"
    tampered_source = b"def get_document(): # compromised source bytes"

    sample_valid_payload["source_digest"] = compute_sha256(genuine_source)

    result = AttestationEngine.verify_attestation(
        sample_valid_payload,
        source_bytes=tampered_source,
    )
    assert result.valid is False
    assert any("Source digest mismatch" in issue for issue in result.issues)


def test_altered_test_outcomes_detected(sample_valid_payload):
    """Test 3: Altered test outcomes (e.g. flipping failed to passed or tampering count) must fail."""
    tampered = copy.deepcopy(sample_valid_payload)
    # Adversary flips one test outcome in results
    tampered["test_results"][1]["outcome"] = "failed"

    result = AttestationEngine.verify_attestation(tampered)
    assert result.valid is False
    # Both reconciliation AND digital signature verification will catch the tampering
    assert any("contradiction" in issue or "signature" in issue or "digest" in issue for issue in result.issues)


def test_missing_tests_detected(sample_valid_payload):
    """Test 4: Missing test records (dropping a test from results list) must fail."""
    tampered = copy.deepcopy(sample_valid_payload)
    # Adversary removes one test record
    tampered["test_results"].pop()

    result = AttestationEngine.verify_attestation(tampered)
    assert result.valid is False
    assert any("Test count contradiction" in issue for issue in result.issues)


def test_modified_approval_records_detected(sample_valid_payload):
    """Test 5: Modified approval records (swapping approver, approval ID) must fail."""
    tampered = copy.deepcopy(sample_valid_payload)
    tampered["approval_id"] = "fraudulent-unauthorized-approval"

    result = AttestationEngine.verify_attestation(
        tampered,
        expected_approval_id="appr-001",
    )
    assert result.valid is False
    assert any("approval" in issue.lower() for issue in result.issues)


def test_invalid_digital_signature_detected(sample_valid_payload):
    """Test 6: Invalid or corrupted digital signatures must fail signature verification."""
    tampered = copy.deepcopy(sample_valid_payload)
    # Corrupt the base64 signature
    orig_sig = tampered["digital_signature"]["signature_base64"]
    # Invert characters in signature string
    corrupted_sig = orig_sig[:-4] + "AAAA"
    tampered["digital_signature"]["signature_base64"] = corrupted_sig

    result = AttestationEngine.verify_attestation(tampered)
    assert result.valid is False
    assert result.signature_valid is False
    assert any("Digital signature verification failed" in issue for issue in result.issues)


def test_unsupported_schema_version_detected(sample_valid_payload):
    """Test 7: Unsupported schema versions must be rejected."""
    tampered = copy.deepcopy(sample_valid_payload)
    tampered["schema_version"] = "sentinel-attestation-v999-unsupported"

    result = AttestationEngine.verify_attestation(tampered)
    assert result.valid is False
    assert any("Unsupported schema version" in issue for issue in result.issues)


def test_wrong_verification_run_detected(sample_valid_payload):
    """Test 8: Evidence referring to the wrong verification run must fail."""
    result = AttestationEngine.verify_attestation(
        sample_valid_payload,
        expected_run_id="run-different-expected-run-999",
    )
    assert result.valid is False
    assert any("wrong verification run" in issue for issue in result.issues)


def test_cryptographic_key_rotation_support(sample_valid_payload):
    """Test 9: Key rotation: signatures signed by older or newer registered keys verify correctly."""
    custom_registry = KeyRegistry()
    # Generate rotated key 2
    rotated_key_id = "sentinel-key-2027-v2"
    new_priv = ed25519.Ed25519PrivateKey.generate()
    custom_registry.register_private_key(rotated_key_id, new_priv)

    # Sign with rotated key
    rotated_attestation = AttestationEngine.create_attestation(
        run_id="run-rotated-001",
        project_id="project-alpha-123",
        job_id="job-test-456",
        target_app_id="bola-demo-v1",
        source_revision="commit-abcdef123456",
        source_digest="sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        patch_hash="sha256:112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00",
        attempt=1,
        patch_id="patch-001",
        approved_by="operator@sentinel-x.local",
        approved_at="2026-10-20T19:00:00Z",
        approval_id="appr-001",
        test_suite_id="bola-required-tests-v1",
        test_suite_version="bola-redteam-v1",
        tests_summary={"total": 1, "passed": 1, "failed": 0, "exit_status": 0, "timed_out": False, "infrastructure_status": "HEALTHY"},
        test_results=[{"name": "test_single", "outcome": "passed", "duration_ms": 1}],
        verdict="VERIFIED",
        key_id=rotated_key_id,
        sign=True,
        registry=custom_registry,
    )

    # Verify with registry containing the rotated key
    res = AttestationEngine.verify_attestation(rotated_attestation, registry=custom_registry)
    assert res.valid is True
    assert res.signature_valid is True
    assert res.key_id == rotated_key_id

    # Verify with registry missing this key (unknown key ID)
    empty_registry = KeyRegistry.__new__(KeyRegistry)
    empty_registry._public_keys = {}
    empty_registry._private_keys = {}
    res_unknown = AttestationEngine.verify_attestation(rotated_attestation, registry=empty_registry)
    assert res_unknown.valid is False
    assert any("Unknown signing key ID" in issue for issue in res_unknown.issues)


def test_claims_and_limitations_documented(sample_valid_payload):
    """Test 10: Explicitly document what the attestation establishes and what it does not prove."""
    claims = sample_valid_payload.get("attestation_claims", {})
    assert "what_it_proves" in claims
    assert "what_it_does_not_prove" in claims

    proves_text = " ".join(claims["what_it_proves"])
    not_proves_text = " ".join(claims["what_it_does_not_prove"])

    # Must state exact patch, test suite, and tamper evidence
    assert "patch hash" in proves_text.lower()
    assert "protected test" in proves_text.lower()

    # Must explicitly state it does NOT certify absence of other vulnerabilities
    assert "absence of undiscovered vulnerabilities" in not_proves_text.lower()
    assert sample_valid_payload["trusted_timestamp"] is False


def test_offline_api_endpoints(sample_valid_payload, tmp_path):
    """Test 11: POST /api/attestation/verify allows independent verification without database/frontend state."""
    from backend.main import create_app
    from backend.config import Settings

    app = create_app(Settings(database_path=tmp_path / "test.db", source_root=tmp_path))
    client = TestClient(app)

    # 1. Verify valid payload
    resp = client.post("/api/attestation/verify", json={"attestation": sample_valid_payload})
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    assert data["signature_valid"] is True
    assert data["algorithm"] == "ed25519"
    assert len(data["issues"]) == 0

    # 2. Verify tampered payload
    tampered = copy.deepcopy(sample_valid_payload)
    tampered["verdict"] = "TAMPERED_VERDICT"
    resp_tampered = client.post("/api/attestation/verify", json={"attestation": tampered})
    assert resp_tampered.status_code == 200
    data_tampered = resp_tampered.json()
    assert data_tampered["valid"] is False
    assert data_tampered["signature_valid"] is False
    assert len(data_tampered["issues"]) > 0
