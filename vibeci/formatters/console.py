"""Console UI formatter for human developers with Rich styling."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.theme import Theme

    custom_theme = Theme({
        "info": "dim cyan",
        "warning": "yellow",
        "error": "bold red",
        "success": "bold green",
    })
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

from vibeci.models import CheckResult, CheckStatus, OverallStatus, VerificationReport


class ConsoleFormatter:
    def __init__(self, console: Optional[Console] = None):
        if sys.platform == "win32":
            try:
                if hasattr(sys.stdout, "reconfigure"):
                    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
                if hasattr(sys.stderr, "reconfigure"):
                    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass

        if HAS_RICH:
            self.console = console or Console(
                theme=custom_theme,
                legacy_windows=False if sys.platform == "win32" else None,
                safe_box=True,
            )
        else:
            self.console = None
        self._status = None

    def render_header(self, project_name: str, project_type: str, total_checks: int) -> None:
        if not HAS_RICH or not self.console:
            print(f"\n--- VibeCI Verification: {project_name} ({project_type}) ---")
            print(f"Running {total_checks} check(s)...\n")
            return

        title_text = Text()
        title_text.append("⚡ VibeCI", style="bold cyan")
        title_text.append(" • Local Verification for AI-Written Code\n", style="dim white")
        title_text.append(f"Project: {project_name}  |  Ecosystem: {project_type}  |  Checks: {total_checks}", style="italic dim")

        self.console.print(Panel(title_text, border_style="cyan", padding=(0, 1)))

    def render_check_start(self, check: Any) -> None:
        name = getattr(check, "name", str(check))
        ctype = getattr(check, "check_type", "")
        ctype_val = getattr(ctype, "value", str(ctype))
        if not HAS_RICH or not self.console:
            print(f"  ⏳ [RUNNING] {name:<16} ...", end="\r", flush=True)
            return

        if self._status:
            self._status.stop()

        self._status = self.console.status(
            Text.assemble(
                ("Running ", "dim"),
                (name, "bold cyan"),
                ("...", "dim"),
            ),
            spinner="dots",
        )
        self._status.start()

    def render_check_result(self, result: CheckResult) -> None:
        duration_sec = f"{result.duration_ms / 1000:.2f}s"

        if self._status:
            self._status.stop()
            self._status = None

        if not HAS_RICH or not self.console:
            sys.stdout.write("\r\x1b[2K")
            sys.stdout.flush()
            status_symbol = {
                CheckStatus.PASSED: "[PASS]",
                CheckStatus.FAILED: "[FAIL]",
                CheckStatus.TIMED_OUT: "[TIMEOUT]",
                CheckStatus.SKIPPED: "[SKIP]",
                CheckStatus.ERROR: "[ERROR]",
            }.get(result.status, "[?]")
            print(f"  {status_symbol:<9} {result.name:<18} ({duration_sec}) - {result.summary}")
            return

        if result.status == CheckStatus.PASSED:
            icon = Text("✔ PASSED", style="bold green")
        elif result.status == CheckStatus.FAILED:
            icon = Text("✘ FAILED", style="bold red")
        elif result.status == CheckStatus.WARNING:
            icon = Text("⚠ WARNING", style="bold yellow")
        elif result.status == CheckStatus.TIMED_OUT:
            icon = Text("⏳ TIMED OUT", style="bold yellow")
        elif result.status == CheckStatus.SKIPPED or result.status == CheckStatus.NOT_CHECKED:
            icon = Text("○ SKIPPED", style="dim")
        else:
            icon = Text("! ERROR", style="bold magenta")

        self.console.print(
            Text.assemble(
                ("  ", ""),
                icon,
                ("  ", ""),
                (f"{result.name:<18}", "bold white"),
                (f" {result.check_type:<10}", "dim cyan"),
                (f" {duration_sec:>7}", "dim"),
                ("  ", ""),
                (result.summary[:65] if result.summary else "", "white"),
            )
        )

    def render_report(self, report: VerificationReport) -> None:
        duration_sec = f"{report.total_duration_ms / 1000:.2f}s"
        summary = report.summary

        # Group findings that need fixing
        issues = [c for c in report.checks if c.status in (CheckStatus.FAILED, CheckStatus.ERROR, CheckStatus.WARNING, CheckStatus.TIMED_OUT)]

        if issues:
            if HAS_RICH and self.console:
                self.console.print("\n[bold red]── What Needs Fixing? ───────────────────────────────────────────[/bold red]")
                for fc in issues:
                    is_warn = fc.status == CheckStatus.WARNING
                    color = "yellow" if is_warn else "red"
                    badge = "[WARNING]" if is_warn else "[FAILED]"

                    content = Text()
                    content.append(f"Issue: {fc.summary}\n", style="bold white")
                    if fc.command and fc.command != "none":
                        content.append(f"Command: {fc.command}\n", style="dim")

                    if fc.file_locations:
                        content.append("\nLocations:\n", style=f"bold {color}")
                        for loc in fc.file_locations[:4]:
                            loc_str = f"  • {loc.file}"
                            if loc.line:
                                loc_str += f":{loc.line}"
                            if loc.column:
                                loc_str += f":{loc.column}"
                            if loc.message:
                                loc_str += f" — {loc.message}"
                            content.append(loc_str + "\n", style=color)

                    if fc.failure_details:
                        content.append("\nKey Output Evidence:\n", style="bold white")
                        for line in fc.failure_details[:5]:
                            content.append(f"  {line}\n", style=color)

                    self.console.print(
                        Panel(
                            content,
                            title=f"[bold {color}]{badge} {fc.name}[/bold {color}]",
                            border_style=color,
                        )
                    )
            else:
                print("\n--- What Needs Fixing? ---")
                for fc in issues:
                    print(f"[{fc.status.value.upper()}] {fc.name}: {fc.summary}")
                    for line in fc.failure_details[:3]:
                        print(f"  {line}")

        # Honest unverified accounting
        if report.unverified:
            if HAS_RICH and self.console:
                self.console.print("\n[dim]── Unverified Capabilities (Honest Boundaries) ─────────────────[/dim]")
                for uv in report.unverified:
                    self.console.print(
                        Text.assemble(
                            ("  ○ ", "dim"),
                            (f"{uv.name:<28}", "bold dim white"),
                            ("— ", "dim"),
                            (uv.reason, "dim italic"),
                        )
                    )
            else:
                print("\nUnverified Capabilities:")
                for uv in report.unverified:
                    print(f"  ○ {uv.name}: {uv.reason}")

        # Final Verdict Banner
        if HAS_RICH and self.console:
            self.console.print()
            stats_text = (
                f"[bold green]{summary['passed']} Passed[/bold green]  •  "
                f"[bold red]{summary['failed']} Failed[/bold red]  •  "
                f"[bold yellow]{summary['warnings']} Warnings[/bold yellow]  •  "
                f"[dim]{summary['not_checked']} Not Checked[/dim]  (in {duration_sec})"
            )

            if report.status == OverallStatus.PASSED:
                verdict = Panel(
                    Text.assemble(
                        ("✔ VERDICT: PASSED", "bold green"),
                        (f"\n{summary['passed']} checks completed with zero defects found. Ready to push.", "dim white"),
                    ),
                    subtitle=stats_text,
                    border_style="green",
                )
            elif report.status == OverallStatus.WARNINGS:
                verdict = Panel(
                    Text.assemble(
                        ("⚠ VERDICT: PASSED WITH WARNINGS", "bold yellow"),
                        (f"\nCore build and tests passed, but {summary['warnings']} configuration warning(s) should be reviewed.", "dim white"),
                    ),
                    subtitle=stats_text,
                    border_style="yellow",
                )
            elif report.status == OverallStatus.FAILED:
                verdict = Panel(
                    Text.assemble(
                        ("✘ VERDICT: FAILED", "bold red"),
                        (f"\n{summary['failed']} check(s) failed. Review evidence above or feed JSON to your AI agent.", "dim white"),
                    ),
                    subtitle=stats_text,
                    border_style="red",
                )
            else:
                verdict = Panel(
                    Text.assemble(
                        ("⚠ VERDICT: INCOMPLETE", "bold yellow"),
                        (f"\n{report.incomplete_reason or 'Verification could not be fully completed.'}", "dim white"),
                    ),
                    subtitle=stats_text,
                    border_style="yellow",
                )

            self.console.print(verdict)
            self.console.print()
        else:
            print(f"\nVERDICT: {report.status.value.upper()} ({summary['passed']} passed, {summary['failed']} failed in {duration_sec})")
