"""Tests for Vercel platform pre-flight check and serverless function limits."""

from pathlib import Path

from vibeci.detectors.vercel import (
    VERCEL_HOBBY_FUNCTION_LIMIT,
    audit_vercel_functions,
    count_serverless_functions,
    is_vercel_project,
)
from vibeci.engine.coordinator import VerificationEngine
from vibeci.models import CheckStatus, OverallStatus


def test_non_vercel_project_returns_none(tmp_path: Path):
    """Test non-Vercel project returns None (zero noise for other projects)."""
    (tmp_path / "package.json").write_text('{"name": "standard-node-app"}')
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "index.js").write_text('console.log("hello");')

    assert is_vercel_project(tmp_path) is False
    assert audit_vercel_functions(tmp_path) is None


def test_vercel_project_under_12_functions_returns_passed_and_ignores_lib(tmp_path: Path):
    """Test Vercel project with < 12 functions returns passed and ignores _lib/ & test files."""
    (tmp_path / "vercel.json").write_text('{"version": 2}')

    # api/ endpoints
    api_dir = tmp_path / "api"
    api_dir.mkdir()
    (api_dir / "hello.ts").write_text("export default function handler() {}")
    (api_dir / "users.js").write_text("module.exports = () => {}")
    (api_dir / "status.py").write_text("def handler(req): return 'ok'")
    (api_dir / "ping.go").write_text("package main")
    (api_dir / "echo.rs").write_text("fn main() {}")

    # Files that MUST be ignored in api/
    lib_dir = api_dir / "_lib"
    lib_dir.mkdir()
    (lib_dir / "db.ts").write_text("export const db = {};")

    internal_dir = api_dir / "_internal"
    internal_dir.mkdir()
    (internal_dir / "helper.py").write_text("def helper(): pass")

    (api_dir / "_helper.js").write_text("module.exports = {};")
    (api_dir / "hello.test.ts").write_text("test('hello', () => {})")
    (api_dir / "users.spec.js").write_text("describe('users', () => {})")
    (api_dir / "types.d.ts").write_text("declare module 'foo';")

    # pages/api/ endpoint
    pages_api_dir = tmp_path / "pages" / "api"
    pages_api_dir.mkdir(parents=True)
    (pages_api_dir / "auth.ts").write_text("export default function auth() {}")
    (pages_api_dir / "_utils.ts").write_text("export const util = 1;")  # ignored

    # app/**/route.ts endpoint
    app_webhook_dir = tmp_path / "app" / "api" / "webhook"
    app_webhook_dir.mkdir(parents=True)
    (app_webhook_dir / "route.ts").write_text("export async function POST() {}")
    (app_webhook_dir / "route.test.ts").write_text("// test")  # ignored
    (app_webhook_dir / "helper.ts").write_text("// not named route.*")  # ignored

    assert is_vercel_project(tmp_path) is True

    endpoints = count_serverless_functions(tmp_path)
    # Expected valid endpoints:
    # 1. api/echo.rs
    # 2. api/hello.ts
    # 3. api/ping.go
    # 4. api/status.py
    # 5. api/users.js
    # 6. app/api/webhook/route.ts
    # 7. pages/api/auth.ts
    assert len(endpoints) == 7

    result = audit_vercel_functions(tmp_path)
    assert result is not None
    assert result.status == CheckStatus.PASSED
    assert "7/12 serverless functions (within Hobby & Pro limits)" in result.summary
    assert result.name == "platform:vercel"

    # Ensure none of the ignored files made it into file_locations
    file_list = [loc.file for loc in result.file_locations]
    assert not any("_lib" in f for f in file_list)
    assert not any("_internal" in f for f in file_list)
    assert not any("_helper" in f for f in file_list)
    assert not any(".test." in f for f in file_list)
    assert not any(".spec." in f for f in file_list)
    assert not any(".d.ts" in f for f in file_list)


def test_vercel_project_over_12_functions_returns_warning(tmp_path: Path):
    """Test Vercel project with > 12 functions returns warning advisory."""
    # Detected via api/ directory
    api_dir = tmp_path / "api"
    api_dir.mkdir()

    # Create 14 serverless function endpoints
    for i in range(1, 15):
        (api_dir / f"endpoint_{i}.ts").write_text(f"export default function h{i}() {{}}")

    assert is_vercel_project(tmp_path) is True

    result = audit_vercel_functions(tmp_path)
    assert result is not None
    assert result.status == CheckStatus.WARNING
    assert "14 serverless functions detected (Safe on Pro; Vercel Hobby allows 12)" in result.summary
    assert any("Hobby plan limit is 12" in line for line in result.failure_details)
    assert any("_lib/" in line for line in result.failure_details)
    assert result.exit_code == 0  # Advisory, not a hard build fail
    assert len(result.file_locations) == 14


def test_vercel_detected_via_dot_vercel_dir(tmp_path: Path):
    """Test project with .vercel directory is recognized as Vercel."""
    (tmp_path / ".vercel").mkdir()
    assert is_vercel_project(tmp_path) is True

    result = audit_vercel_functions(tmp_path)
    assert result is not None
    assert result.status == CheckStatus.PASSED
    assert "0/12 serverless functions" in result.summary


def test_vercel_integration_with_verification_engine(tmp_path: Path):
    """Test platform:vercel check is executed and reported by VerificationEngine."""
    (tmp_path / "vercel.json").write_text("{}")
    api_dir = tmp_path / "api"
    api_dir.mkdir()
    for i in range(13):
        (api_dir / f"fn_{i}.js").write_text("module.exports = () => {}")

    engine = VerificationEngine(tmp_path)
    report = engine.verify(run_build=False, run_tests=False)

    check_names = [c.name for c in report.checks]
    assert "platform:vercel" in check_names

    vercel_check = next(c for c in report.checks if c.name == "platform:vercel")
    assert vercel_check.status == CheckStatus.WARNING
    assert report.status == OverallStatus.WARNINGS
    assert report.summary["warnings"] == 1
