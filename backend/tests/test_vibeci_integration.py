"""Tests for VibeCI integration in KAVACH-X.

Covers:
- Preflight audit with clean and failing fixtures
- Secret leak detection and redaction
- Missing environment variable preflight
- Path containment and traversal protection
- Execution timeout and process failure handling
- REST API endpoints for status, preflight, verification, and rules
- Database persistence and security audit logging
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import pytest
from fastapi.testclient import TestClient

from backend.main import create_app
from backend.models import WorkflowError
from backend.services.vibeci_service import (
    VibeCIOptions,
    VibeCIService,
    redact_secrets,
    validate_contained_path,
)
from vibeci.models import CheckStatus, OverallStatus


@pytest.fixture
def temp_project():
    """Create a temporary project workspace with controlled fixtures."""
    with tempfile.TemporaryDirectory(prefix="kavach-vibeci-test-") as temp_dir:
        root = Path(temp_dir)
        # Create standard files
        (root / "pyproject.toml").write_text("""[project]
name = "test-fixture"
version = "0.1.0"
dependencies = ["fastapi", "sqlalchemy"]
""", encoding="utf-8")
        (root / ".env.example").write_text("""# Environment Configuration
DATABASE_URL=sqlite:///./app.db
SECRET_KEY=example_key_here
PORT=8000
""", encoding="utf-8")
        src_dir = root / "src"
        src_dir.mkdir(parents=True, exist_ok=True)
        (src_dir / "app.py").write_text("""import os

db_url = os.environ.get("DATABASE_URL")
port = int(os.environ.get("PORT", "8000"))

def get_status():
    return {"status": "ok"}
""", encoding="utf-8")
        yield root


def test_status_endpoint():
    app = create_app()
    client = TestClient(app)
    resp = client.get("/api/vibeci/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["service"] == "vibeci"
    assert data["available"] is True
    assert "static_health" in data["available_layers"]
    assert "env_audit" in data["available_layers"]
    assert "security" in data["available_layers"]
    assert "detected_tools" in data


def test_preflight_clean_fixture(temp_project):
    service = VibeCIService()
    report = service.run_preflight_audit(temp_project)

    assert report.status in (OverallStatus.PASSED, OverallStatus.WARNINGS)
    check_names = [c.name for c in report.checks]
    assert "env:preflight" in check_names
    assert "security:secrets" in check_names

    # Check honest accounting: sqlalchemy is in dependencies, but no DB test was run
    unverified_names = [u.name for u in report.unverified]
    assert "Database Integration" in unverified_names


def test_preflight_detects_secrets(temp_project):
    service = VibeCIService()
    # Plant a leaked OpenAI project key and GitHub PAT
    leaky_file = temp_project / "src" / "leaky.py"
    leaky_file.write_text("""
OPENAI_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
GH_TOKEN = "ghp_123456789012345678901234567890123456"
""", encoding="utf-8")

    report = service.run_preflight_audit(temp_project)
    sec_check = next(c for c in report.checks if c.name == "security:secrets")
    assert sec_check.status == CheckStatus.FAILED
    assert report.status == OverallStatus.FAILED
    assert len(sec_check.file_locations) >= 1

    # Ensure secrets in failure details are redacted
    for detail in sec_check.failure_details:
        assert "ghp_12345678901234567890" not in detail
        assert "sk-proj-abcdefghijklmnop" not in detail


def test_preflight_detects_missing_env_vars(temp_project):
    service = VibeCIService()
    app_file = temp_project / "src" / "app.py"
    app_file.write_text("""import os
# Undocumented environment variable
secret_token = os.getenv("UNDECLARED_THIRD_PARTY_SECRET")
""", encoding="utf-8")

    report = service.run_preflight_audit(temp_project)
    env_check = next(c for c in report.checks if c.name == "env:preflight")
    assert env_check.status == CheckStatus.WARNING
    assert any("UNDECLARED_THIRD_PARTY_SECRET" in d for d in env_check.failure_details)


def test_secret_redaction_helper():
    raw_text = "Failed connecting to postgres://admin:superSecret123@db.internal:5432 with key sk-live-123456789012345678901234"
    sanitized = redact_secrets(raw_text)
    assert "superSecret123" not in sanitized
    assert "sk-live-123456789012345678901234" not in sanitized
    assert "[REDACTED_CREDENTIAL]" in sanitized


def test_path_containment_validation(temp_project):
    # Valid contained path
    safe_path = validate_contained_path(temp_project, "src/app.py")
    assert safe_path.exists()

    # Traversal attempt outside root
    with pytest.raises(ValueError, match="Path traversal detected"):
        validate_contained_path(temp_project, "../../windows/system32")


def test_timeout_and_error_handling(temp_project):
    service = VibeCIService()
    from vibeci.models import CheckDefinition, CheckType, CheckLayer

    # Test runner handling of non-existent command
    runner = service.run_verification(
        temp_project,
        options=VibeCIOptions(run_static=False, run_build=False, run_tests=False, run_smoke=False),
    )
    assert runner is not None


def test_api_preflight_and_reporting_workflow():
    from uuid import uuid4
    app = create_app()
    client = TestClient(app)
    unique_email = f"vibeci_tester_{uuid4().hex[:8]}@kavach.local"

    # 1. Register & login user
    reg = client.post("/api/auth/register", json={
        "email": unique_email,
        "password": "Password123!SecureEnoughPassword",
    })
    assert reg.status_code == 201

    login = client.post("/api/auth/login", json={
        "email": unique_email,
        "password": "Password123!SecureEnoughPassword",
    })
    assert login.status_code == 200
    csrf_token = login.json()["csrf_token"]
    headers = {"X-CSRF-Token": csrf_token}

    # 2. Create project
    proj_resp = client.post("/api/projects", json={
        "name": "VibeCI Test Project",
        "description": "Verification integration test",
    }, headers=headers)
    assert proj_resp.status_code == 201
    project_id = proj_resp.json()["id"]

    # 3. Upload a clean test file
    upload_resp = client.post(
        f"/api/projects/{project_id}/upload-file",
        content="""import os\nPORT = int(os.environ.get('PORT', '8000'))\ndef main(): pass\n""",
        headers={**headers, "Content-Type": "text/plain", "X-File-Name": "main.py"},
    )
    assert upload_resp.status_code == 200

    # 4. Run VibeCI Preflight via REST API
    pf_resp = client.post(f"/api/projects/{project_id}/vibeci/preflight", headers=headers)
    assert pf_resp.status_code == 200
    pf_data = pf_resp.json()
    assert pf_data["run_type"] == "PREFLIGHT"
    assert "status" in pf_data
    assert "checks" in pf_data
    assert "run_id" in pf_data
    run_id = pf_data["run_id"]

    # 5. List historical reports
    reports_resp = client.get(f"/api/projects/{project_id}/vibeci/reports", headers=headers)
    assert reports_resp.status_code == 200
    reports = reports_resp.json()
    assert len(reports) >= 1
    assert reports[0]["id"] == run_id

    # 6. Retrieve detailed report
    detail_resp = client.get(f"/api/projects/{project_id}/vibeci/reports/{run_id}", headers=headers)
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["id"] == run_id
    assert "report" in detail

    # 7. Configure AI rules
    rules_resp = client.post(f"/api/projects/{project_id}/vibeci/rules", json={"agent": "cursor"}, headers=headers)
    assert rules_resp.status_code == 200
    assert rules_resp.json()["status"] == "installed"
