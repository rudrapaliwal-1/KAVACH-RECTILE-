"""Tests for VibeCI project check detectors."""

import json
from pathlib import Path

import pytest

from vibeci.detectors.javascript import JavaScriptDetector
from vibeci.detectors.python import PythonDetector
from vibeci.models import CheckLayer, CheckType


def test_python_detector_with_pytest_and_ruff(tmp_path: Path):
    # Setup mock python project
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
name = "test-pkg"
version = "0.1.0"

[tool.pytest.ini_options]
minversion = "7.0"

[tool.ruff]
line-length = 88
""",
        encoding="utf-8",
    )
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_sample.py").write_text("def test_ok(): pass\n")

    detector = PythonDetector()
    assert detector.is_applicable(tmp_path) is True

    checks = detector.detect(tmp_path)
    check_names = [c.name for c in checks]
    assert "pytest" in check_names
    assert "ruff" in check_names


def test_javascript_detector_with_npm_scripts(tmp_path: Path):
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(
        json.dumps({
            "name": "mock-js-project",
            "scripts": {
                "test": "vitest run",
                "lint": "eslint .",
                "typecheck": "tsc --noEmit",
            },
        }),
        encoding="utf-8",
    )

    detector = JavaScriptDetector()
    assert detector.is_applicable(tmp_path) is True

    checks = detector.detect(tmp_path)
    check_names = [c.name for c in checks]
    assert any("test" in name for name in check_names)
    assert any("lint" in name for name in check_names)
    assert any("typecheck" in name for name in check_names)


def test_javascript_detector_ignores_npm_dummy_test(tmp_path: Path):
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(
        json.dumps({
            "name": "mock-js-project",
            "scripts": {
                "test": 'echo "Error: no test specified" && exit 1',
            },
        }),
        encoding="utf-8",
    )

    detector = JavaScriptDetector()
    checks = detector.detect(tmp_path)
    # The dummy test should be filtered out
    assert not any("test" in c.name for c in checks)


@pytest.mark.parametrize("lockfile", ["bun.lock", "bun.lockb"])
@pytest.mark.parametrize("dummy_script", [False, True])
def test_javascript_detector_with_bun_lockfile(
    tmp_path: Path, lockfile: str, dummy_script: bool
):
    (tmp_path / lockfile).touch()
    if dummy_script:
        (tmp_path / "package.json").write_text(
            json.dumps({"scripts": {"test": 'echo "Error: no test specified" && exit 1'}}),
            encoding="utf-8",
        )

    detector = JavaScriptDetector()
    assert detector.is_applicable(tmp_path)
    checks = detector.detect(tmp_path)

    assert len(checks) == 1
    check = checks[0]
    assert check.name == "bun:test"
    assert check.command == ["bun", "test"]
    assert check.layer == CheckLayer.BEHAVIOR
    assert check.check_type == CheckType.TEST
    assert check.cwd == tmp_path
    assert check.required


@pytest.mark.parametrize("script_name", ["test", "test:unit", "test-unit"])
@pytest.mark.parametrize(
    ("script", "expected_args"),
    [
        ("bun test", []),
        ('bun test --coverage "./unit tests"', ["--coverage", "./unit tests"]),
        ("bun test --watch", []),
        ("bun --watch test --coverage", ["--coverage"]),
        ("bun test --hot ./unit", ["./unit"]),
        ("bun test --watch -t --watch", ["-t", "--watch"]),
        ("bun test --hot --test-name-pattern --hot", ["--test-name-pattern", "--hot"]),
        ("bun test --watch -- --watch", ["--", "--watch"]),
    ],
)
def test_javascript_detector_with_bun_test_script(
    tmp_path: Path, script_name: str, script: str, expected_args: list[str]
):
    (tmp_path / "package.json").write_text(
        json.dumps({"scripts": {script_name: script}}), encoding="utf-8"
    )

    checks = JavaScriptDetector().detect(tmp_path)

    assert len(checks) == 1
    assert checks[0].name == f"bun:{script_name}"
    assert checks[0].command == ["bun", "test", *expected_args]
    assert checks[0].layer == CheckLayer.BEHAVIOR
    assert checks[0].check_type == CheckType.TEST


@pytest.mark.parametrize("config", ["vitest.config.ts", "jest.config.js"])
def test_javascript_detector_prefers_configured_runner_to_bun_lockfile(
    tmp_path: Path, config: str
):
    (tmp_path / "bun.lock").touch()
    (tmp_path / config).touch()

    checks = JavaScriptDetector().detect(tmp_path)

    assert len(checks) == 1
    assert checks[0].name == config.split(".")[0]


@pytest.mark.parametrize(
    "script",
    ["vitest run", 'echo "bun test"', "bun test ./unit && bun test ./integration", r"bun test .\unit"],
)
def test_javascript_detector_preserves_other_test_scripts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, script: str
):
    monkeypatch.setattr("vibeci.detectors.javascript.shutil.which", lambda tool: f"/usr/bin/{tool}")
    (tmp_path / "bun.lock").touch()
    (tmp_path / "package.json").write_text(
        json.dumps({"scripts": {"test": script}}), encoding="utf-8"
    )

    checks = JavaScriptDetector().detect(tmp_path)

    assert len(checks) == 1
    assert checks[0].command == ["bun", "run", "test"]


def test_javascript_detector_does_not_duplicate_bun_test_script(tmp_path: Path):
    (tmp_path / "bun.lock").touch()
    (tmp_path / "package.json").write_text(
        json.dumps({"scripts": {"test": "bun test"}}), encoding="utf-8"
    )

    checks = JavaScriptDetector().detect(tmp_path)

    assert len(checks) == 1
    assert checks[0].command == ["bun", "test"]


@pytest.mark.parametrize("hook", ["pretest", "posttest"])
def test_javascript_detector_preserves_bun_test_lifecycle_hooks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, hook: str
):
    monkeypatch.setattr("vibeci.detectors.javascript.shutil.which", lambda tool: f"/usr/bin/{tool}")
    (tmp_path / "package.json").write_text(
        json.dumps({"scripts": {"test": "bun test", hook: "node setup.js"}}), encoding="utf-8"
    )

    checks = JavaScriptDetector().detect(tmp_path)

    assert len(checks) == 1
    assert checks[0].command == ["npm", "run", "--silent", "test"]
