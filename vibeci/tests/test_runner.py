"""Tests for VibeCI runner and result parsing."""

import sys
from pathlib import Path

from vibeci.models import CheckDefinition, CheckStatus, CheckType, OverallStatus
from vibeci.runner import CheckRunner


def test_runner_passing_check(tmp_path: Path):
    runner = CheckRunner(root_dir=tmp_path)
    check = CheckDefinition(
        name="test-pass",
        command=[sys.executable, "-c", "print('All tests passed successfully.')"],
        check_type=CheckType.TEST,
    )
    result = runner.run_check(check)
    assert result.status == CheckStatus.PASSED
    assert result.exit_code == 0
    assert "passed" in result.summary.lower()


def test_runner_failing_check_with_error_location(tmp_path: Path):
    runner = CheckRunner(root_dir=tmp_path)
    # Output simulating a linter/compiler error with path:line:col
    script = (
        "import sys\n"
        "sys.stderr.write('src/main.py:12:5: SyntaxError: invalid syntax\\n')\n"
        "sys.exit(1)\n"
    )
    check = CheckDefinition(
        name="test-fail",
        command=[sys.executable, "-c", script],
        check_type=CheckType.LINT,
    )
    result = runner.run_check(check)
    assert result.status == CheckStatus.FAILED
    assert result.exit_code == 1
    assert len(result.file_locations) > 0
    assert result.file_locations[0].file == "src/main.py"
    assert result.file_locations[0].line == 12
    assert result.file_locations[0].column == 5


def test_runner_timeout(tmp_path: Path):
    runner = CheckRunner(root_dir=tmp_path)
    check = CheckDefinition(
        name="test-timeout",
        command=[sys.executable, "-c", "import time; time.sleep(5)"],
        check_type=CheckType.TEST,
        timeout_seconds=1,
    )
    result = runner.run_check(check)
    assert result.status == CheckStatus.TIMED_OUT
    assert "timed out" in result.summary.lower()


def test_runner_caching_and_failed_only(tmp_path: Path):
    runner = CheckRunner(root_dir=tmp_path)
    check_pass = CheckDefinition(
        name="c-pass",
        command=[sys.executable, "-c", "exit(0)"],
        check_type=CheckType.TEST,
    )
    check_fail = CheckDefinition(
        name="c-fail",
        command=[sys.executable, "-c", "exit(1)"],
        check_type=CheckType.TEST,
    )

    report = runner.run_all([check_pass, check_fail])
    assert report.status == OverallStatus.FAILED

    # Check that failed checks are recorded in cache
    failed_names = runner.get_last_failed_check_names()
    assert failed_names == ["c-fail"]

    # Rerun with failed_only
    rerun_report = runner.run_all([check_pass, check_fail], failed_only=True)
    assert len(rerun_report.checks) == 1
    assert rerun_report.checks[0].name == "c-fail"
