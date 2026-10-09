"""
Command Line Interface (CLI) for GitGhost.
Copyright 2026 EvoderDev. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import os
import sys

# Ensure UTF-8 stream handling on Windows systems (e.g. Turkish CP1254, CP437)
if sys.platform == "win32":
    if sys.stdout and hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if sys.stderr and hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

from typing import List, Optional
import fnmatch
import click
import yaml

from gitghost.core.ast_scanner import ASTScanner
from gitghost.core.diff_parser import DiffParser, get_git_diff
from gitghost.core.secret_detector import SecretDetector
from gitghost.engine.patch_generator import PatchGenerator
from gitghost.engine.review_agent import ReviewAgent
from gitghost.integrators.github_client import GitHubClient
from gitghost.models import DiffFile, Finding, ScanReport, Severity
from gitghost.ui.console import GitGhostConsole


def load_config(config_path: str = ".gitghost.yaml") -> dict:
    """Loads configuration file if present."""
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception:
            return {}
    return {}


def is_path_excluded(path: str, patterns: List[str]) -> bool:
    """Checks if a file path matches any exclusion glob pattern."""
    norm = path.replace("\\", "/")
    for pat in patterns:
        norm_pat = pat.replace("\\", "/")
        if fnmatch.fnmatch(norm, norm_pat) or fnmatch.fnmatch(os.path.basename(norm), norm_pat):
            return True
        prefix = norm_pat.replace("/**", "").replace("/*", "")
        if prefix and (norm == prefix or norm.startswith(prefix + "/")):
            return True
    return False


def run_scan_pipeline(
    diff_text: str = "",
    file_path: Optional[str] = None,
    min_severity_str: str = "low",
    base_dir: str = ".",
) -> ScanReport:
    """Executes Secret and AST analysis pipeline."""
    report = ScanReport()
    findings: List[Finding] = []

    cfg = load_config()
    exclude_patterns = cfg.get("exclude_patterns", [])

    secret_detector = SecretDetector()
    ast_scanner = ASTScanner()

    # Mode 1: File or Directory direct scan
    if file_path:
        target_path = os.path.join(base_dir, file_path) if not os.path.isabs(file_path) else file_path
        if os.path.isdir(target_path):
            files_to_scan = []
            for root, _, filenames in os.walk(target_path):
                for fname in filenames:
                    rel_p = os.path.relpath(os.path.join(root, fname), base_dir)
                    if is_path_excluded(rel_p, exclude_patterns):
                        continue
                    if fname.endswith((".py", ".js", ".ts", ".go", ".sh", ".json", ".yaml", ".yml", ".env")):
                        files_to_scan.append(os.path.join(root, fname))
            report.scanned_files_count = len(files_to_scan)
            for f in files_to_scan:
                try:
                    with open(f, "r", encoding="utf-8", errors="replace") as handle:
                        content = handle.read()
                    findings.extend(secret_detector.scan_text(f, content))
                    findings.extend(ast_scanner.scan_source(f, content))
                except Exception:
                    pass
        elif os.path.isfile(target_path):
            if is_path_excluded(file_path, exclude_patterns):
                return _finalize_report(report, findings, min_severity_str)
            report.scanned_files_count = 1
            try:
                with open(target_path, "r", encoding="utf-8", errors="replace") as handle:
                    content = handle.read()
                findings.extend(secret_detector.scan_text(file_path, content))
                findings.extend(ast_scanner.scan_source(file_path, content))
            except Exception:
                pass
        return _finalize_report(report, findings, min_severity_str)

    # Mode 2: Git Diff Scan
    if not diff_text.strip():
        return report

    parser = DiffParser(diff_text)
    diff_files = parser.parse()
    active_diff_files = [df for df in diff_files if not is_path_excluded(df.target_path, exclude_patterns)]
    report.scanned_files_count = len(active_diff_files)

    for df in active_diff_files:
        if df.is_binary:
            continue
        # 1. Scan for secrets in added lines
        sec_findings = secret_detector.scan_diff_file(df)
        findings.extend(sec_findings)

        # 2. AST semantic scanning
        ast_findings = ast_scanner.scan_diff_file(df, base_dir=base_dir)
        findings.extend(ast_findings)

    return _finalize_report(report, findings, min_severity_str)


def _finalize_report(report: ScanReport, findings: List[Finding], min_severity_str: str) -> ScanReport:
    """Filters findings by severity and calculates metrics."""
    min_sev = Severity[min_severity_str.upper()]
    filtered = [f for f in findings if f.severity >= min_sev]
    report.findings = filtered
    report.calculate_metrics()
    return report


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option("1.0.0", prog_name="GitGhost")
def cli():
    """GitGhost: Autonomous Git Diff, AST & Secret Security Scanner with LLM Patch Engine."""
    pass


@cli.command("scan")
@click.option("--staged", is_flag=True, help="Scan staged git changes (git diff --staged).")
@click.option("--commit", type=str, default=None, help="Scan a specific commit SHA.")
@click.option("--branch", type=str, default=None, help="Compare current branch with base branch.")
@click.option("--file", "target_file", type=str, default=None, help="Scan a specific file or folder directly.")
@click.option("--format", "output_format", type=click.Choice(["rich", "json", "sarif", "markdown"]), default="rich", help="Output format.")
@click.option("--output", "output_file", type=click.Path(), default=None, help="Save report to file.")
@click.option("--min-severity", default="low", type=click.Choice(["info", "low", "medium", "high", "critical"], case_sensitive=False), help="Minimum severity to report.")
@click.option("--fail-on", default="high", type=click.Choice(["info", "low", "medium", "high", "critical"], case_sensitive=False), help="Exit with code 1 if severity reached.")
@click.option("--details", is_flag=True, help="Display full vulnerability details card.")
def scan_cmd(staged, commit, branch, target_file, output_format, output_file, min_severity, fail_on, details):
    """Scan git diff or files for secret leaks and AST vulnerabilities."""
    ui = GitGhostConsole()
    if output_format == "rich":
        ui.print_banner()

    diff_content = ""
    if not target_file:
        diff_content = get_git_diff(staged=staged, commit=commit, base_ref=branch)
        if not diff_content.strip() and output_format == "rich":
            ui.console.print("[dim yellow]No git diff detected. Run with '--staged' or provide '--file <PATH>'.[/dim yellow]")

    report = run_scan_pipeline(diff_text=diff_content, file_path=target_file, min_severity_str=min_severity)

    fail_threshold = Severity[fail_on.upper()]
    should_fail = any(f.severity >= fail_threshold for f in report.findings)

    # Output formatting
    if output_format == "rich":
        ui.render_findings_table(report.findings)
        if details:
            for f in report.findings:
                ui.render_finding_detail(f)
        ui.render_summary(report)

    elif output_format == "json":
        json_output = report.to_json()
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(json_output)
        else:
            click.echo(json_output)

    elif output_format == "sarif":
        sarif_json = report.model_dump_json(indent=2) if hasattr(report, "sarif") else str(report.to_sarif())
        import json
        sarif_formatted = json.dumps(report.to_sarif(), indent=2)
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(sarif_formatted)
        else:
            click.echo(sarif_formatted)

    elif output_format == "markdown":
        gh_client = GitHubClient()
        md_output = gh_client.format_markdown_summary(report)
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(md_output)
        else:
            click.echo(md_output)

    if should_fail:
        sys.exit(1)


@cli.command("fix")
@click.option("--staged", is_flag=True, help="Scan staged git changes.")
@click.option("--file", "target_file", type=str, default=None, help="Target specific file.")
@click.option("--apply", "auto_apply", is_flag=True, help="Automatically apply generated patches.")
@click.option("--interactive/--no-interactive", default=True, help="Prompt before applying each patch.")
@click.option("--output-patch", type=click.Path(), default=None, help="Save unified patch to a file.")
def fix_cmd(staged, target_file, auto_apply, interactive, output_patch):
    """Autonomously generate and apply unified patches for detected flaws."""
    ui = GitGhostConsole()
    ui.print_banner()

    diff_content = ""
    if not target_file:
        diff_content = get_git_diff(staged=staged)

    report = run_scan_pipeline(diff_text=diff_content, file_path=target_file)
    if not report.findings:
        ui.console.print("✨ [bold green]No security flaws detected. No patches needed.[/bold green]")
        return

    ui.render_findings_table(report.findings)

    patcher = PatchGenerator()
    patches = patcher.generate_all_patches(report.findings)

    if not patches:
        ui.console.print("[dim yellow]No deterministic patches could be generated for these findings.[/dim yellow]")
        return

    ui.console.print(f"🛠️ [bold cyan]Generated {len(patches)} autonomous patch proposal(s).[/bold cyan]\n")

    combined_diff = "\n\n".join(p.unified_diff for p in patches)
    if output_patch:
        with open(output_patch, "w", encoding="utf-8") as f:
            f.write(combined_diff)
        ui.console.print(f"💾 [green]Saved patch to {output_patch}[/green]")

    for p in patches:
        if auto_apply:
            PatchGenerator.apply_patch(p)
            ui.console.print(f"✅ [bold green]Applied patch to {p.file_path}[/bold green]")
        elif interactive:
            if ui.confirm_apply(p):
                PatchGenerator.apply_patch(p)
                ui.console.print(f"✅ [bold green]Applied patch to {p.file_path}[/bold green]")
            else:
                ui.console.print(f"⏭️ [dim]Skipped {p.file_path}[/dim]")
        else:
            ui.render_diff(p.unified_diff)


@cli.command("review")
@click.option("--provider", default="auto", type=click.Choice(["auto", "openai", "anthropic", "gemini", "ollama", "offline"], case_sensitive=False), help="LLM Provider.")
@click.option("--model", default=None, type=str, help="Specific model name.")
@click.option("--staged", is_flag=True, help="Scan staged changes.")
def review_cmd(provider, model, staged):
    """Run Autonomous LLM Review Agent on git diff & findings."""
    ui = GitGhostConsole()
    ui.print_banner()

    diff_content = get_git_diff(staged=staged)
    parser = DiffParser(diff_content)
    diff_files = parser.parse()

    report = run_scan_pipeline(diff_text=diff_content)
    agent = ReviewAgent(provider_name=provider, model=model)

    with ui.console.status("[bold cyan]GitGhost Autonomous Review Agent analyzing code changes...[/bold cyan]"):
        review_data = agent.review(diff_files, report.findings, raw_diff=diff_content)

    ui.console.print(f"\n[bold magenta]Review Agent Executive Summary:[/bold magenta]\n{review_data.get('summary')}\n")
    ui.console.print(f"Risk Score: [bold red]{review_data.get('risk_score', 0)}/100[/bold red]")
    ui.console.print(f"Agent Status: [bold]{review_data.get('agent_status', 'UNKNOWN')}[/bold]\n")

    recs = review_data.get("recommendations", [])
    if recs:
        ui.console.print("[bold cyan]Key Recommendations:[/bold cyan]")
        for r in recs:
            ui.console.print(f"  • {r}")


@cli.command("ci")
@click.option("--fail-on", default="high", type=click.Choice(["info", "low", "medium", "high", "critical"], case_sensitive=False), help="Exit code 1 threshold.")
def ci_cmd(fail_on):
    """GitHub Action / CI Pipeline execution entrypoint."""
    ui = GitGhostConsole()
    gh = GitHubClient()

    event_data = gh.get_action_event_data()
    pr_number = event_data.get("pull_request", {}).get("number")
    commit_sha = os.environ.get("GITHUB_SHA", "HEAD")

    diff_content = ""
    if pr_number and gh.is_configured:
        try:
            diff_content = gh.get_pr_diff(pr_number)
        except Exception as exc:
            ui.console.print(f"[dim red]Failed fetching PR diff via API: {exc}. Falling back to git diff.[/dim red]")
            diff_content = get_git_diff()
    else:
        diff_content = get_git_diff()

    report = run_scan_pipeline(diff_text=diff_content)
    patcher = PatchGenerator()
    report.patches = patcher.generate_all_patches(report.findings)

    # Write step summary for GitHub Action UI
    gh.write_step_summary(report)

    # Post PR review if configured
    if pr_number and gh.is_configured and report.findings:
        try:
            summary_body = gh.format_markdown_summary(report)
            event_type = "REQUEST_CHANGES" if not report.passed else "COMMENT"
            gh.submit_pr_review(pr_number, commit_sha, summary_body, event=event_type)
        except Exception as exc:
            ui.console.print(f"[dim red]Could not submit PR review comment: {exc}[/dim red]")

    ui.render_summary(report)

    fail_threshold = Severity[fail_on.upper()]
    if any(f.severity >= fail_threshold for f in report.findings):
        sys.exit(1)


@cli.command("init")
def init_cmd():
    """Initializes .gitghost.yaml and installs pre-commit hook."""
    ui = GitGhostConsole()
    config_file = ".gitghost.yaml"
    if not os.path.exists(config_file):
        default_cfg = {
            "version": "1.0",
            "min_severity": "low",
            "fail_on": "high",
            "secrets": {"enabled": True, "min_entropy": 4.3},
            "ast": {"enabled": True},
            "engine": {"provider": "auto", "generate_patches": True},
        }
        with open(config_file, "w", encoding="utf-8") as f:
            yaml.safe_dump(default_cfg, f)
        ui.console.print(f"✅ [green]Created {config_file}[/green]")
    else:
        ui.console.print(f"ℹ️ [dim]{config_file} already exists.[/dim]")

    # Hook installation
    git_hooks_dir = os.path.join(".git", "hooks")
    if os.path.exists(git_hooks_dir):
        hook_path = os.path.join(git_hooks_dir, "pre-commit")
        hook_script = "#!/bin/sh\n# GitGhost Pre-Commit Security Gate\ngitghost scan --staged --fail-on high\n"
        with open(hook_path, "w", encoding="utf-8") as f:
            f.write(hook_script)
        try:
            os.chmod(hook_path, 0o755)
        except Exception:
            pass
        ui.console.print("✅ [green]Installed Git pre-commit hook in .git/hooks/pre-commit[/green]")


def main():
    """Unified entrypoint for gitghost and gh-ghost."""
    cli()


if __name__ == "__main__":
    main()
