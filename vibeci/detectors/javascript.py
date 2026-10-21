"""Detector for JavaScript and TypeScript projects (npm, pnpm, yarn, bun, vitest, jest, eslint, tsc, biome)."""

from __future__ import annotations

import json
import shlex
import shutil
from pathlib import Path
from typing import Any, List, Optional

from vibeci.detectors.base import BaseDetector
from vibeci.models import CheckDefinition, CheckLayer, CheckType


class JavaScriptDetector(BaseDetector):
    name: str = "javascript"

    def is_applicable(self, root_dir: Path) -> bool:
        indicators = [
            "package.json",
            "tsconfig.json",
            "jsconfig.json",
            "pnpm-lock.yaml",
            "yarn.lock",
            "bun.lockb",
            "bun.lock",
        ]
        return any((root_dir / ind).exists() for ind in indicators)

    def _detect_package_manager(self, root_dir: Path) -> tuple[str, list[str]]:
        """Return (pm_name, run_command_prefix)."""
        if (root_dir / "pnpm-lock.yaml").exists() and shutil.which("pnpm"):
            return "pnpm", ["pnpm", "run"]
        if (root_dir / "yarn.lock").exists() and shutil.which("yarn"):
            return "yarn", ["yarn", "run"]
        if ((root_dir / "bun.lockb").exists() or (root_dir / "bun.lock").exists()) and shutil.which("bun"):
            return "bun", ["bun", "run"]
        if shutil.which("npm"):
            return "npm", ["npm", "run", "--silent"]
        # Fallback
        return "npm", ["npm", "run"]

    def _get_exec_prefix(self, pm: str) -> list[str]:
        if pm == "pnpm" and shutil.which("pnpm"):
            return ["pnpm", "exec"]
        if pm == "yarn" and shutil.which("yarn"):
            return ["yarn", "run"]
        if pm == "bun" and shutil.which("bun"):
            return ["bun", "x"]
        if shutil.which("npx"):
            return ["npx", "--no-install"]
        return ["npm", "exec"]

    def _get_bun_test_command(self, script: str) -> Optional[list[str]]:
        """Return a single Bun test command for a simple script."""
        if any(char in script for char in "&|;<>()`$\\"):
            return None
        try:
            args = shlex.split(script)
        except ValueError:
            return None

        # Preserve option values and positional arguments when removing reload flags.
        value_options = {
            "-t", "--test-name-pattern", "-r", "--preload", "--coverage-dir",
            "--coverage-reporter", "--reporter", "--reporter-outfile",
            "--path-ignore-patterns", "--cwd", "--env-file", "--config",
        }
        command: list[str] = []
        takes_value = False
        for index, arg in enumerate(args):
            if arg == "--" and not takes_value:
                command.extend(args[index:])
                break
            if takes_value or arg not in ("--watch", "--hot"):
                command.append(arg)
                takes_value = not takes_value and arg in value_options
        return command if command[:2] == ["bun", "test"] else None

    def detect(self, root_dir: Path) -> list[CheckDefinition]:
        checks: list[CheckDefinition] = []
        pkg_json_file = root_dir / "package.json"

        pkg_data: dict[str, Any] = {}
        scripts: dict[str, str] = {}
        if pkg_json_file.exists():
            try:
                pkg_data = json.loads(pkg_json_file.read_text(encoding="utf-8"))
                scripts = pkg_data.get("scripts", {})
            except Exception:
                pass

        pm, pm_run = self._detect_package_manager(root_dir)
        exec_prefix = self._get_exec_prefix(pm)

        # 1. Test check(s)
        # Find all test scripts (e.g. "test", "test:unit", "test:events", "test:e2e")
        test_script_names = [
            k for k in scripts.keys()
            if (k == "test" or k.startswith("test:") or k.startswith("test-"))
            and "no test specified" not in scripts[k]
        ]

        if test_script_names:
            for sname in test_script_names:
                bun_command = self._get_bun_test_command(scripts[sname])
                if f"pre{sname}" in scripts or f"post{sname}" in scripts:
                    bun_command = None
                checks.append(
                    CheckDefinition(
                        name=f"bun:{sname}" if bun_command else f"{pm}:{sname}",
                        command=bun_command or pm_run + [sname],
                        layer=(CheckLayer.BEHAVIOR if bun_command else CheckLayer.CUSTOM),
                        check_type=CheckType.TEST,
                        cwd=root_dir,
                        description=(
                            "Run tests with Bun" if bun_command
                            else f"Run tests using `{pm} run {sname}`"
                        ),
                        required=True,
                        discovered_by="javascript-detector",
                    )
                )
        else:
            # Check for Turborepo
            has_turbo_json = (root_dir / "turbo.json").exists()
            turbo_has_test = False
            if has_turbo_json:
                try:
                    turbo_data = json.loads((root_dir / "turbo.json").read_text(encoding="utf-8"))
                    tasks = turbo_data.get("tasks", turbo_data.get("pipeline", {}))
                    if "test" in tasks:
                        turbo_has_test = True
                except Exception:
                    pass

            if turbo_has_test:
                checks.append(
                    CheckDefinition(
                        name="turbo:test",
                        command=exec_prefix + ["turbo", "run", "test"],
                        check_type=CheckType.TEST,
                        cwd=root_dir,
                        description="Run Turborepo tests across workspaces (`turbo run test`)",
                        required=True,
                        discovered_by="javascript-detector",
                    )
                )
            else:
                # Check for direct test runner configs
                has_vitest = any((root_dir / f"vitest.config.{ext}").exists() for ext in ("ts", "js", "mjs", "mts"))
                has_jest = any((root_dir / f"jest.config.{ext}").exists() for ext in ("ts", "js", "mjs", "cjs", "json"))

                if has_vitest:
                    checks.append(
                        CheckDefinition(
                            name="vitest",
                            command=exec_prefix + ["vitest", "run"],
                            check_type=CheckType.TEST,
                            cwd=root_dir,
                            description="Run tests with Vitest",
                            required=True,
                            discovered_by="javascript-detector",
                        )
                    )
                elif has_jest:
                    checks.append(
                        CheckDefinition(
                            name="jest",
                            command=exec_prefix + ["jest"],
                            check_type=CheckType.TEST,
                            cwd=root_dir,
                            required=True,
                            discovered_by="javascript-detector",
                        )
                    )
                elif (root_dir / "bun.lock").exists() or (root_dir / "bun.lockb").exists():
                    checks.append(
                        CheckDefinition(
                            name="bun:test",
                            command=["bun", "test"],
                            layer=CheckLayer.BEHAVIOR,
                            check_type=CheckType.TEST,
                            cwd=root_dir,
                            description="Run tests with Bun",
                            required=True,
                            discovered_by="javascript-detector",
                        )
                    )

        # 2. Typecheck check
        typecheck_script_name = next(
            (k for k in ("typecheck", "type-check", "check-types", "tsc") if k in scripts),
            None,
        )
        if typecheck_script_name:
            checks.append(
                CheckDefinition(
                    name=f"{pm}:{typecheck_script_name}",
                    command=pm_run + [typecheck_script_name],
                    check_type=CheckType.TYPECHECK,
                    cwd=root_dir,
                    description=f"Run type checking using `{pm} run {typecheck_script_name}`",
                    required=True,
                    discovered_by="javascript-detector",
                )
            )
        elif (root_dir / "tsconfig.json").exists():
            # If TypeScript is configured, run tsc --noEmit
            checks.append(
                CheckDefinition(
                    name="tsc",
                    command=exec_prefix + ["tsc", "--noEmit"],
                    check_type=CheckType.TYPECHECK,
                    cwd=root_dir,
                    description="Run TypeScript compiler check (`tsc --noEmit`)",
                    required=True,
                    discovered_by="javascript-detector",
                )
            )

        # 3. Lint check
        lint_script_name = next((k for k in ("lint", "lint:check", "check") if k in scripts and k != typecheck_script_name), None)
        if lint_script_name:
            checks.append(
                CheckDefinition(
                    name=f"{pm}:{lint_script_name}",
                    command=pm_run + [lint_script_name],
                    check_type=CheckType.LINT,
                    cwd=root_dir,
                    description=f"Run linter using `{pm} run {lint_script_name}`",
                    required=True,
                    discovered_by="javascript-detector",
                )
            )
        else:
            # Check for Biome or ESLint configs
            has_biome = (root_dir / "biome.json").exists() or (root_dir / "biome.jsonc").exists()
            has_eslint = any(
                (root_dir / name).exists()
                for name in (
                    "eslint.config.js",
                    "eslint.config.mjs",
                    "eslint.config.cjs",
                    ".eslintrc.js",
                    ".eslintrc.json",
                    ".eslintrc.yaml",
                    ".eslintrc.yml",
                    ".eslintrc",
                )
            )

            if has_biome:
                checks.append(
                    CheckDefinition(
                        name="biome",
                        command=exec_prefix + ["@biomejs/biome", "check", "."],
                        check_type=CheckType.LINT,
                        cwd=root_dir,
                        description="Check code with Biome linter/formatter",
                        required=True,
                        discovered_by="javascript-detector",
                    )
                )
            elif has_eslint:
                checks.append(
                    CheckDefinition(
                        name="eslint",
                        command=exec_prefix + ["eslint", "."],
                        check_type=CheckType.LINT,
                        cwd=root_dir,
                        description="Lint code with ESLint",
                        required=True,
                        discovered_by="javascript-detector",
                    )
                )

        return checks
