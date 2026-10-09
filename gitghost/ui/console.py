"""
Rich Interactive Terminal Console for GitGhost.
Copyright 2026 EvoderDev. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import sys
from typing import List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.syntax import Syntax
from rich.prompt import Confirm

from gitghost.models import Finding, PatchProposal, ScanReport, Severity


class GitGhostConsole:
    """Rich-based terminal UI renderer."""

    BANNER = r"""
   ____ _ _    ____ _               _   
  / ___(_) |_ / ___| |__   ___  ___| |_ 
 | |  _| | __| |  _| '_ \ / _ \/ __| __|
 | |_| | | |_| |_| | | | | (_) \__ \ |_ 
  \____|_|\__|\____|_| |_|\___/|___/\__|
"""

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()

    def print_banner(self) -> None:
        """Displays ASCII banner and header information."""
        banner_text = Text(self.BANNER, style="bold cyan")
        subtitle = Text("Autonomous DevSecOps & AST Patch Engine (Apache 2.0 - EvoderDev 2026)\n", style="italic dim magenta")
        self.console.print(banner_text)
        self.console.print(subtitle)

    @staticmethod
    def get_severity_badge(severity: Severity) -> Text:
        """Returns stylized Rich badge for severity."""
        if severity == Severity.CRITICAL:
            return Text(" CRITICAL ", style="bold white on red")
        elif severity == Severity.HIGH:
            return Text("   HIGH   ", style="bold white on dark_orange")
        elif severity == Severity.MEDIUM:
            return Text("  MEDIUM  ", style="bold black on yellow")
        elif severity == Severity.LOW:
            return Text("   LOW    ", style="bold white on blue")
        else:
            return Text("   INFO   ", style="bold white on cyan")

    def render_findings_table(self, findings: List[Finding]) -> None:
        """Renders summary table of all security findings."""
        if not findings:
            self.console.print(Panel("✨ [bold green]All clear![/bold green] No security vulnerabilities or leaked secrets detected.", border_style="green"))
            return

        table = Table(
            title="🔍 Detected Vulnerabilities & Secret Leaks",
            title_style="bold magenta",
            header_style="bold cyan",
            border_style="dim blue",
            expand=True,
        )
        table.add_column("ID", style="dim", width=10)
        table.add_column("Severity", justify="center", width=12)
        table.add_column("Category", style="cyan", width=18)
        table.add_column("Location", style="yellow", width=25)
        table.add_column("Title", style="bold white")

        for f in findings:
            badge = self.get_severity_badge(f.severity)
            loc = f"{f.file_path}:{f.line_number}"
            table.add_row(f.id, badge, f.category.value, loc, f.title)

        self.console.print(table)
        self.console.print()

    def render_finding_detail(self, finding: Finding) -> None:
        """Renders single finding detail card with code and remediation."""
        content = Text()
        content.append(f"Rule: {finding.rule_id}  |  Category: {finding.category.value}\n", style="dim cyan")
        if finding.owasp_tag:
            content.append(f"OWASP: {finding.owasp_tag}  |  CWE: {finding.cwe or 'N/A'}\n", style="dim yellow")
        content.append(f"\n{finding.description}\n\n", style="white")

        if finding.snippet:
            content.append(f"Problematic Code ({finding.file_path}:{finding.line_number}):\n", style="bold red")
            content.append(f"  {finding.snippet}\n\n", style="bright_red")

        content.append(f"Remediation Advice:\n", style="bold green")
        content.append(f"  {finding.remediation}\n", style="dim green")

        if finding.suggested_fix:
            content.append(f"\nAutonomous Fix Template:\n", style="bold magenta")
            content.append(f"  {finding.suggested_fix}\n", style="bright_magenta")

        sev_color = "red" if finding.severity in (Severity.CRITICAL, Severity.HIGH) else "yellow"
        panel = Panel(
            content,
            title=f"[{sev_color}]Finding {finding.id}: {finding.title}[/{sev_color}]",
            border_style=sev_color,
            expand=True,
        )
        self.console.print(panel)

    def render_diff(self, diff_text: str) -> None:
        """Renders unified diff with syntax highlighting."""
        if not diff_text.strip():
            return
        syntax = Syntax(diff_text, "diff", theme="monokai", line_numbers=True)
        self.console.print(Panel(syntax, title="📝 Unified Patch", border_style="cyan"))

    def render_summary(self, report: ScanReport) -> None:
        """Renders overall execution summary card."""
        color = "green" if report.passed else "red"
        status_text = "[bold green]PASSED[/bold green]" if report.passed else "[bold red]FAILED (BLOCKING)[/bold red]"

        critical_count = sum(1 for f in report.findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in report.findings if f.severity == Severity.HIGH)
        medium_count = sum(1 for f in report.findings if f.severity == Severity.MEDIUM)
        low_count = sum(1 for f in report.findings if f.severity in (Severity.LOW, Severity.INFO))

        summary_text = (
            f"Result: {status_text}   |   Risk Score: [bold {color}]{report.risk_score}/100[/bold {color}]\n"
            f"Files Scanned: [cyan]{report.scanned_files_count}[/cyan]   |   Total Findings: [bold]{len(report.findings)}[/bold]\n"
            f"Breakdown: [red]{critical_count} Critical[/red]  [dark_orange]{high_count} High[/dark_orange]  "
            f"[yellow]{medium_count} Medium[/yellow]  [blue]{low_count} Low/Info[/blue]\n"
            f"Autonomous Patches: [magenta]{len(report.patches)}[/magenta] available"
        )
        self.console.print(Panel(summary_text, title="👻 GitGhost Executive Summary", border_style=color))

    def confirm_apply(self, patch: PatchProposal) -> bool:
        """Prompts user to confirm applying a patch."""
        self.console.print(f"\n[bold yellow]Target File:[/bold yellow] {patch.file_path}")
        self.render_diff(patch.unified_diff)
        return Confirm.ask(f"Apply autonomous patch to [bold]{patch.file_path}[/bold]?", default=True)
