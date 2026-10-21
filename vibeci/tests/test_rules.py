"""Unit tests for VibeCI AI agent rule generator."""

from pathlib import Path
from vibeci.rules import install_rules, get_rule_status, VIBECI_RULE_HEADER


def test_install_rules_all(tmp_path: Path):
    installed = install_rules(tmp_path, agent="all")
    assert ".cursorrules" in installed
    assert "CLAUDE.md" in installed
    assert ".github/copilot-instructions.md" in installed
    assert "AGENTS.md" in installed

    # Check rule status
    status = get_rule_status(tmp_path)
    assert status[".cursorrules"] is True
    assert status["CLAUDE.md"] is True
    assert status["AGENTS.md"] is True

    # Re-running should be idempotent
    re_installed = install_rules(tmp_path, agent="all")
    assert len(re_installed) == 0


def test_install_rules_cursor_only(tmp_path: Path):
    installed = install_rules(tmp_path, agent="cursor")
    assert ".cursorrules" in installed
    assert not (tmp_path / "CLAUDE.md").exists()


def test_append_preserves_existing_instructions(tmp_path: Path):
    claude_file = tmp_path / "CLAUDE.md"
    claude_file.write_text("# Project Custom Rules\nAlways be concise.\n")

    install_rules(tmp_path, agent="claude")

    content = claude_file.read_text()
    assert "# Project Custom Rules" in content
    assert "Always be concise." in content
    assert VIBECI_RULE_HEADER in content
    assert "vibeci verify --diff --json" in content


def test_install_rules_antigravity(tmp_path: Path):
    installed = install_rules(tmp_path, agent="antigravity")
    assert ".agents/rules/vibeci.md" in installed
    assert "AGENTS.md" in installed
    assert (tmp_path / ".agents" / "rules" / "vibeci.md").exists()
    assert (tmp_path / "AGENTS.md").exists()

