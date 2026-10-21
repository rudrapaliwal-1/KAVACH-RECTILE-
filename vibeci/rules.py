"""AI Agent Rule Generator for VibeCI.

Automates configuring AI assistants (Cursor, Claude Code, GitHub Copilot, Codex)
to automatically run VibeCI after changes and inspect the structured JSON report.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

VIBECI_RULE_HEADER = "<!-- VIBECI:AI-RULE:START -->"
VIBECI_RULE_FOOTER = "<!-- VIBECI:AI-RULE:END -->"

VIBECI_RULE_CONTENT = f"""{VIBECI_RULE_HEADER}
# VibeCI AI Verification Protocol

You must verify your code changes using VibeCI before declaring any task complete:

1. **Run Verification Command**:
   Execute `vibeci verify --diff --json` in your terminal after modifying or creating code files.

2. **Inspect the JSON Output**:
   - Check the `"status"` field:
     - `"passed"`: All checks passed with zero defects. You may proceed.
     - `"failed"` or `"warnings"`: Defects detected. Must be fixed immediately.
   - For any check in `"checks"` with `"status": "failed"`:
     - Read `"file_locations"` for exact `file`, `line`, and `column` coordinates.
     - Read `"failure_details"` for compiler/linter error messages and stack traces.
     - Check `"security:secrets"`: Remove hardcoded API keys, secrets, or DB passwords.
     - Check `"env:preflight"`: Add missing referenced environment variables to `.env.example`.

3. **Self-Correction Loop**:
   - Apply fixes to the specific files and line numbers reported in `file_locations`.
   - Never weaken or delete tests to bypass verification.
   - Re-run `vibeci verify --diff --json` until `"status": "passed"`.
   - Do NOT declare the task complete or tell the user the task is done until `vibeci verify` passes.
{VIBECI_RULE_FOOTER}"""

CURSOR_MDC_CONTENT = f"""---
description: Always verify code changes with VibeCI
globs: *
alwaysApply: true
---

{VIBECI_RULE_CONTENT}
"""


def _append_or_replace_rule(target_path: Path, content: str) -> bool:
    """Safely append or update VibeCI rules in a file without destroying existing user instructions."""
    if not target_path.exists():
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(content.strip() + "\n", encoding="utf-8")
        return True

    existing = target_path.read_text(encoding="utf-8")
    if existing.strip() == content.strip():
        return False

    if VIBECI_RULE_HEADER in existing and VIBECI_RULE_FOOTER in existing:
        start_idx = existing.find(VIBECI_RULE_HEADER)
        end_idx = existing.find(VIBECI_RULE_FOOTER) + len(VIBECI_RULE_FOOTER)
        current_block = existing[start_idx:end_idx]
        if current_block.strip() == content.strip():
            return False
        updated = existing[:start_idx].rstrip() + "\n\n" + content.strip() + "\n" + existing[end_idx:].lstrip()
        target_path.write_text(updated.strip() + "\n", encoding="utf-8")
        return True
    elif "vibeci verify" in existing:
        # Already has custom vibeci instructions
        return False
    else:
        # Append to existing instructions
        updated = existing.rstrip() + "\n\n" + content.strip() + "\n"
        target_path.write_text(updated, encoding="utf-8")
        return True


def install_rules(root_dir: Path, agent: str = "all") -> list[str]:
    """Install VibeCI rules for specified agent(s).

    Supported agent targets:
    - 'all': Installs into Cursor (.cursorrules & .cursor/rules), Claude Code (CLAUDE.md),
      GitHub Copilot (.github/copilot-instructions.md), and universal AGENTS.md.
    - 'cursor': .cursorrules and .cursor/rules/vibeci.mdc
    - 'claude': CLAUDE.md
    - 'copilot': .github/copilot-instructions.md
    - 'universal': AGENTS.md
    """
    root_dir = root_dir.resolve()
    installed_files: list[str] = []

    # 1. Cursor
    if agent in ("all", "cursor"):
        cursorrules = root_dir / ".cursorrules"
        if _append_or_replace_rule(cursorrules, VIBECI_RULE_CONTENT):
            installed_files.append(".cursorrules")

        cursor_rules_dir = root_dir / ".cursor" / "rules"
        cursor_mdc = cursor_rules_dir / "vibeci.mdc"
        if _append_or_replace_rule(cursor_mdc, CURSOR_MDC_CONTENT):
            installed_files.append(".cursor/rules/vibeci.mdc")

    # 2. Claude Code
    if agent in ("all", "claude"):
        claude_md = root_dir / "CLAUDE.md"
        if _append_or_replace_rule(claude_md, VIBECI_RULE_CONTENT):
            installed_files.append("CLAUDE.md")

    # 3. GitHub Copilot
    if agent in ("all", "copilot"):
        copilot_md = root_dir / ".github" / "copilot-instructions.md"
        if _append_or_replace_rule(copilot_md, VIBECI_RULE_CONTENT):
            installed_files.append(".github/copilot-instructions.md")

    # 4. Universal AGENTS.md
    if agent in ("all", "universal"):
        agents_md = root_dir / "AGENTS.md"
        if _append_or_replace_rule(agents_md, VIBECI_RULE_CONTENT):
            installed_files.append("AGENTS.md")

    # 5. Antigravity (.agents/rules/vibeci.md & AGENTS.md)
    if agent in ("all", "antigravity"):
        antigravity_rule = root_dir / ".agents" / "rules" / "vibeci.md"
        if _append_or_replace_rule(antigravity_rule, VIBECI_RULE_CONTENT):
            installed_files.append(".agents/rules/vibeci.md")
        agents_md = root_dir / "AGENTS.md"
        if "AGENTS.md" not in installed_files:
            if _append_or_replace_rule(agents_md, VIBECI_RULE_CONTENT):
                installed_files.append("AGENTS.md")

    return installed_files


def get_rule_status(root_dir: Path) -> dict[str, bool]:
    """Return status of rule files in the given directory."""
    root_dir = root_dir.resolve()
    targets = {
        ".cursorrules": root_dir / ".cursorrules",
        ".cursor/rules/vibeci.mdc": root_dir / ".cursor" / "rules" / "vibeci.mdc",
        "CLAUDE.md": root_dir / "CLAUDE.md",
        ".github/copilot-instructions.md": root_dir / ".github" / "copilot-instructions.md",
        "AGENTS.md": root_dir / "AGENTS.md",
        ".agents/rules/vibeci.md": root_dir / ".agents" / "rules" / "vibeci.md",
    }
    status = {}
    for name, path in targets.items():
        if path.exists() and ("vibeci verify" in path.read_text(errors="ignore")):
            status[name] = True
        else:
            status[name] = False
    return status
