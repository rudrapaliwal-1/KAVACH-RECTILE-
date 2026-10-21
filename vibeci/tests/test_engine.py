"""Unit tests for VibeCI multi-layer verification engine."""

from pathlib import Path
import pytest

from vibeci.engine.coordinator import VerificationEngine
from vibeci.engine.health.env_audit import EnvAuditor
from vibeci.engine.health.secret_scan import SecretScanner
from vibeci.engine.runtime.smoke_tester import RuntimeSmokeTester
from vibeci.models import CheckStatus


def test_secret_scanner_detects_aws_and_github_keys(tmp_path: Path):
    dummy_aws = "AKIA" + "1234567890ABCDEF"
    leaky_file = tmp_path / "leak.js"
    leaky_file.write_text(f"const aws_key = '{dummy_aws}';\n")

    scanner = SecretScanner(tmp_path)
    result = scanner.scan()
    assert result.status == CheckStatus.FAILED
    assert len(result.file_locations) > 0
    assert result.file_locations[0].file == "leak.js"


@pytest.mark.parametrize(
    "secret_line,expected_desc",
    [
        ("OPENAI_KEY = '" + "sk-" + "proj-" + ("a" * 48) + "'", "OpenAI Project API Key"),
        ("ANTHROPIC_KEY = '" + "sk-" + "ant-" + "api03-" + ("b" * 80) + "'", "Anthropic Claude API Key"),
        ("GEMINI_KEY = '" + "AIza" + ("c" * 35) + "'", "Google API / Gemini Key"),
        ("HF_TOKEN = '" + "hf_" + ("d" * 34) + "'", "Hugging Face Token"),
        ("STRIPE_KEY = '" + "sk_" + "live_" + ("e" * 24) + "'", "Stripe Live Secret Key"),
        ("SLACK_WEBHOOK = '" + "https://" + "hooks." + "slack.com/services/T123/B456/" + ("f" * 24) + "'", "Slack Incoming Webhook URL"),
        ("SLACK_TOKEN = '" + "xoxb-" + "123456789012-" + "1234567890123-" + ("g" * 24) + "'", "Slack Bot / Access Token"),
    ],
)
def test_secret_scanner_expanded_patterns(tmp_path: Path, secret_line: str, expected_desc: str):
    f = tmp_path / "config.py"
    f.write_text(f"{secret_line}\n")
    scanner = SecretScanner(tmp_path)
    result = scanner.scan()
    assert result.status == CheckStatus.FAILED
    assert any(expected_desc in det for det in result.failure_details)


def test_env_auditor_flags_missing_example_vars(tmp_path: Path):
    (tmp_path / ".env.example").write_text("PORT=3000\n")
    code_file = tmp_path / "app.js"
    code_file.write_text("const secret = process.env.CUSTOM_NEW_SECRET;\n")

    auditor = EnvAuditor(tmp_path)
    result = auditor.audit()
    assert result.status == CheckStatus.WARNING
    assert "CUSTOM_NEW_SECRET" in result.summary or any("CUSTOM_NEW_SECRET" in d for d in result.failure_details)


def test_env_auditor_vite_import_meta_env(tmp_path: Path):
    (tmp_path / ".env.example").write_text("VITE_APP_TITLE=MyApp\n")
    vite_file = tmp_path / "App.vue"
    vite_file.write_text("const apiUrl = import.meta.env.VITE_BACKEND_URL;\n")

    auditor = EnvAuditor(tmp_path)
    result = auditor.audit()
    assert result.status == CheckStatus.WARNING
    assert any("VITE_BACKEND_URL" in d for d in result.failure_details)


def test_env_auditor_python_square_bracket_and_sample_template(tmp_path: Path):
    # Using .env.sample instead of .env.example
    (tmp_path / ".env.sample").write_text("PORT=8000\n")
    py_file = tmp_path / "server.py"
    py_file.write_text("db_pass = os.environ['DB_PASSWORD']\n")

    auditor = EnvAuditor(tmp_path)
    result = auditor.audit()
    assert result.status == CheckStatus.WARNING
    assert any("DB_PASSWORD" in d for d in result.failure_details)
    assert any(".env.sample" in d for d in result.failure_details)


def test_runtime_smoke_tester_detects_fastapi(tmp_path: Path):
    main_py = tmp_path / "main.py"
    main_py.write_text("from fastapi import FastAPI\napp = FastAPI()\n")

    tester = RuntimeSmokeTester(tmp_path)
    cmd, port = tester.detect_start_command()
    assert "uvicorn" in cmd
    assert "main:app" in cmd
    assert port == 8000


def test_runtime_smoke_tester_detects_django(tmp_path: Path):
    manage_py = tmp_path / "manage.py"
    manage_py.write_text("#!/usr/bin/env python\n")

    tester = RuntimeSmokeTester(tmp_path)
    cmd, port = tester.detect_start_command()
    assert "runserver" in cmd
    assert port == 8000


def test_runtime_smoke_tester_detects_flask(tmp_path: Path):
    app_py = tmp_path / "app.py"
    app_py.write_text("from flask import Flask\napp = Flask(__name__)\n")

    tester = RuntimeSmokeTester(tmp_path)
    cmd, port = tester.detect_start_command()
    assert "app.py" in cmd
    assert port == 5000


def test_verification_engine_honest_unverified_accounting(tmp_path: Path):
    # Setup project with database dependency and stripe API, but no db or e2e tests
    (tmp_path / "package.json").write_text('{"dependencies": {"mongoose": "^7.0.0", "stripe": "^12.0.0", "react": "^18.0.0"}}')
    engine = VerificationEngine(tmp_path)
    unverified = engine.identify_unverified_capabilities([])
    names = [u.name for u in unverified]
    assert "Database Integration" in names
    assert "External Third-Party APIs" in names
    assert "End-to-End Browser Flows" in names


def test_verification_engine_pure_cli_no_false_unverified(tmp_path: Path):
    # Setup pure CLI / library project with no DB, API, or frontend deps
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "mycli"\ndependencies = ["click", "rich"]\n')
    engine = VerificationEngine(tmp_path)
    unverified = engine.identify_unverified_capabilities([])
    assert len(unverified) == 0
