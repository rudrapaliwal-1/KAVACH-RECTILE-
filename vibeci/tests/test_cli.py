"""Tests for VibeCI CLI commands."""

import json
from pathlib import Path

from vibeci.cli import build_parser, handle_check, handle_doctor, handle_init


def test_cli_init_command(tmp_path: Path):
    parser = build_parser()
    args = parser.parse_args(["init", "-C", str(tmp_path)])
    code = handle_init(args)
    assert code == 0
    config_file = tmp_path / ".vibeci.toml"
    assert config_file.exists()
    assert "timeout_seconds" in config_file.read_text()


def test_cli_check_json_output(tmp_path: Path, capsys):
    # Setup mock python project with a test that passes
    (tmp_path / "pyproject.toml").write_text("[project]\nname='demo'\nversion='0.1.0'\n")
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_simple.py").write_text("def test_ok(): assert 1 == 1\n")

    parser = build_parser()
    args = parser.parse_args(["check", "--json", "-C", str(tmp_path)])
    code = handle_check(args)

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "status" in data
    assert "checks" in data
    assert "summary" in data


def test_cli_doctor(tmp_path: Path, capsys):
    parser = build_parser()
    args = parser.parse_args(["doctor", "-C", str(tmp_path)])
    code = handle_doctor(args)
    assert code == 0
    captured = capsys.readouterr()
    assert "VibeCI Doctor" in captured.out


def test_cli_help_subcommand(capsys):
    from vibeci.cli import handle_help
    parser = build_parser()

    # Generic help
    args = parser.parse_args(["help"])
    assert handle_help(parser, args) == 0
    out = capsys.readouterr().out
    assert "Available subcommands" in out

    # Subcommand specific help
    args_verify = parser.parse_args(["help", "verify"])
    assert handle_help(parser, args_verify) == 0
    out_verify = capsys.readouterr().out
    assert "--diff" in out_verify

    # Unknown subcommand
    args_bad = parser.parse_args(["help", "nonexistent"])
    assert handle_help(parser, args_bad) == 1


def test_cli_upgrade_up_to_date(monkeypatch, capsys):
    from vibeci.cli import handle_upgrade
    parser = build_parser()

    monkeypatch.setattr("vibeci.cli.get_latest_pypi_version", lambda pkg: "0.3.0")
    args = parser.parse_args(["upgrade"])
    assert handle_upgrade(args) == 0
    captured = capsys.readouterr().out
    assert "already up to date" in captured


def test_cli_upgrade_newer_available_check(monkeypatch, capsys):
    from vibeci.cli import handle_upgrade
    parser = build_parser()

    monkeypatch.setattr("vibeci.cli.get_latest_pypi_version", lambda pkg: "0.4.0")
    args = parser.parse_args(["upgrade", "--check"])
    assert handle_upgrade(args) == 0
    captured = capsys.readouterr().out
    assert "New version available" in captured
    assert "0.3.0 → v0.4.0" in captured


def test_cli_upgrade_dry_run(monkeypatch, capsys):
    from vibeci.cli import handle_upgrade
    parser = build_parser()

    monkeypatch.setattr("vibeci.cli.get_latest_pypi_version", lambda pkg: "0.4.0")
    args = parser.parse_args(["upgrade", "--dry-run"])
    assert handle_upgrade(args) == 0
    captured = capsys.readouterr().out
    assert "Would execute:" in captured


def test_cli_upgrade_network_error(monkeypatch, capsys):
    from vibeci.cli import handle_upgrade
    parser = build_parser()

    monkeypatch.setattr("vibeci.cli.get_latest_pypi_version", lambda pkg: None)
    args = parser.parse_args(["upgrade"])
    assert handle_upgrade(args) == 1
    captured = capsys.readouterr().out
    assert "Could not check for updates" in captured


def test_cli_typo_normalization(monkeypatch):
    import sys
    from vibeci.cli import main

    dispatched = []
    monkeypatch.setattr("vibeci.cli.handle_upgrade", lambda args: dispatched.append("upgrade") or 0)
    monkeypatch.setattr("vibeci.cli.handle_help", lambda p, args: dispatched.append("help") or 0)
    monkeypatch.setattr(sys, "exit", lambda code: None)

    main(["-updrade"])
    assert "upgrade" in dispatched

    main(["--upgrade"])
    assert dispatched.count("upgrade") == 2

    main(["-help"])
    assert "help" in dispatched

