"""Configuration management for VibeCI."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # type: ignore
    except ImportError:
        tomllib = None  # type: ignore

from vibeci.models import CheckDefinition, CheckType


@dataclass
class VibeConfig:
    timeout_seconds: int = 120
    fail_fast: bool = False
    ignore_checks: list[str] = field(default_factory=list)
    custom_checks: list[CheckDefinition] = field(default_factory=list)
    trust_discovered: bool = True

    @classmethod
    def load(cls, root_dir: Path) -> VibeConfig:
        config = cls()
        config_file = root_dir / ".vibeci.toml"
        pyproject_file = root_dir / "pyproject.toml"

        data: dict[str, Any] = {}

        if config_file.exists() and tomllib:
            try:
                data = tomllib.loads(config_file.read_text(encoding="utf-8"))
            except Exception:
                pass
        elif pyproject_file.exists() and tomllib:
            try:
                pyproj = tomllib.loads(pyproject_file.read_text(encoding="utf-8"))
                data = pyproj.get("tool", {}).get("vibeci", {})
            except Exception:
                pass

        if not data:
            return config

        settings = data.get("settings", data)
        config.timeout_seconds = int(settings.get("timeout_seconds", config.timeout_seconds))
        config.fail_fast = bool(settings.get("fail_fast", config.fail_fast))
        config.ignore_checks = list(settings.get("ignore_checks", []))
        config.trust_discovered = bool(settings.get("trust_discovered", config.trust_discovered))

        # Parse custom checks
        custom_raw = data.get("checks", [])
        if isinstance(custom_raw, list):
            for item in custom_raw:
                if isinstance(item, dict) and "name" in item and "command" in item:
                    cmd = item["command"]
                    if isinstance(cmd, str):
                        cmd_list = cmd.split()
                    else:
                        cmd_list = list(cmd)
                    raw_type = item.get("type", "custom").lower()
                    try:
                        ctype = CheckType(raw_type)
                    except ValueError:
                        ctype = CheckType.CUSTOM

                    config.custom_checks.append(
                        CheckDefinition(
                            name=item["name"],
                            command=cmd_list,
                            check_type=ctype,
                            cwd=root_dir / item.get("cwd", "."),
                            timeout_seconds=item.get("timeout_seconds"),
                            description=item.get("description", ""),
                            required=item.get("required", True),
                            discovered_by="config",
                        )
                    )

        return config


STARTER_CONFIG = """# VibeCI Configuration (.vibeci.toml)
# Local Verification for AI-Written Code

[settings]
# Max duration in seconds per check before timing out
timeout_seconds = 60

# Stop execution immediately on the first failed check
fail_fast = false

# Names of checks to ignore/skip (e.g. ["flake8", "npm:build"])
ignore_checks = []

# Trust auto-discovered commands (pytest, vitest, eslint, etc.)
trust_discovered = true

# Optional: Add custom project checks
# [[checks]]
# name = "security-scan"
# command = "bandit -r src/"
# type = "lint"
# description = "Run security audit"
"""


def create_starter_config(target_dir: Path) -> Path:
    config_path = target_dir / ".vibeci.toml"
    if not config_path.exists():
        config_path.write_text(STARTER_CONFIG, encoding="utf-8")
    return config_path
