"""
GitHub Actions and Pull Request API Integration Client.
Copyright 2026 EvoderDev. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional
import requests

from gitghost.models import Finding, ScanReport, Severity


class GitHubClient:
    """Client for GitHub REST API in CI/CD and Pull Request reviews."""

    def __init__(
        self,
        token: Optional[str] = None,
        repository: Optional[str] = None,
        api_url: str = "https://api.github.com",
    ):
        self.token = token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        self.repository = repository or os.environ.get("GITHUB_REPOSITORY")
        self.api_url = api_url.rstrip("/")

        self.headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "GitGhost-DevSecOps/1.0",
        }
        if self.token:
            self.headers["Authorization"] = f"Bearer {self.token}"

    @property
    def is_configured(self) -> bool:
        return bool(self.token and self.repository)

    @staticmethod
    def get_action_event_data() -> Dict[str, Any]:
        """Parses the GitHub Action event payload from GITHUB_EVENT_PATH."""
        event_path = os.environ.get("GITHUB_EVENT_PATH")
        if event_path and os.path.exists(event_path):
            try:
                with open(event_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def get_pr_diff(self, pr_number: int) -> str:
        """Fetches the raw unified diff for a Pull Request."""
        if not self.is_configured:
            raise ValueError("GitHubClient requires GITHUB_TOKEN and GITHUB_REPOSITORY.")

        url = f"{self.api_url}/repos/{self.repository}/pulls/{pr_number}"
        diff_headers = dict(self.headers)
        diff_headers["Accept"] = "application/vnd.github.v3.diff"

        resp = requests.get(url, headers=diff_headers, timeout=30)
        resp.raise_for_status()
        return resp.text

    def post_issue_comment(self, issue_or_pr_number: int, body: str) -> Dict[str, Any]:
        """Posts a markdown comment to a Pull Request or Issue."""
        if not self.is_configured:
            raise ValueError("GitHubClient requires GITHUB_TOKEN and GITHUB_REPOSITORY.")

        url = f"{self.api_url}/repos/{self.repository}/issues/{issue_or_pr_number}/comments"
        resp = requests.post(url, headers=self.headers, json={"body": body}, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def submit_pr_review(
        self,
        pr_number: int,
        commit_sha: str,
        body: str,
        event: str = "COMMENT",  # APPROVE, REQUEST_CHANGES, COMMENT
        inline_comments: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Submits a comprehensive Pull Request review with inline comments."""
        if not self.is_configured:
            raise ValueError("GitHubClient requires GITHUB_TOKEN and GITHUB_REPOSITORY.")

        url = f"{self.api_url}/repos/{self.repository}/pulls/{pr_number}/reviews"
        payload: Dict[str, Any] = {
            "commit_id": commit_sha,
            "body": body,
            "event": event,
        }
        if inline_comments:
            payload["comments"] = inline_comments

        resp = requests.post(url, headers=self.headers, json=payload, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def write_step_summary(self, report: ScanReport) -> None:
        """Appends a Markdown summary to $GITHUB_STEP_SUMMARY."""
        summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
        if not summary_file:
            return

        markdown = self.format_markdown_summary(report)
        try:
            with open(summary_file, "a", encoding="utf-8") as f:
                f.write(markdown)
                f.write("\n\n")
        except Exception:
            pass

    def write_step_outputs(self, report: ScanReport) -> None:
        """Writes findings_count and risk_score outputs to $GITHUB_OUTPUT for action.yml."""
        output_file = os.environ.get("GITHUB_OUTPUT")
        if not output_file:
            return
        try:
            with open(output_file, "a", encoding="utf-8") as f:
                f.write(f"findings_count={len(report.findings)}\n")
                f.write(f"risk_score={report.risk_score}\n")
        except Exception:
            pass

    def format_markdown_summary(self, report: ScanReport) -> str:
        """Formats the scan report into GitHub Actions Markdown."""
        status_badge = "🟢 **PASS**" if report.passed else "🔴 **BLOCK**"
        lines = [
            "# 👻 GitGhost Security & Quality Report",
            f"**Status:** {status_badge} | **Risk Score:** `{report.risk_score}/100` | **Scanned Files:** `{report.scanned_files_count}`",
            "",
        ]

        if not report.findings:
            lines.append("🎉 **No vulnerabilities, secret leaks, or performance defects found!**")
            return "\n".join(lines)

        lines.extend([
            "### 🚨 Findings Overview",
            "| Severity | Category | Rule | File & Line | Title |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])

        severity_icons = {
            Severity.CRITICAL: "🔴 CRITICAL",
            Severity.HIGH: "🟠 HIGH",
            Severity.MEDIUM: "🟡 MEDIUM",
            Severity.LOW: "🔵 LOW",
            Severity.INFO: "⚪ INFO",
        }

        for f in report.findings:
            sev = severity_icons.get(f.severity, f.severity.value)
            loc = f"`{f.file_path}:{f.line_number}`"
            lines.append(f"| {sev} | `{f.category.value}` | `{f.rule_id}` | {loc} | {f.title} |")

        lines.append("")
        lines.append("### 🔍 Detailed Breakdown")
        for idx, f in enumerate(report.findings, start=1):
            lines.append(f"<details><summary><b>#{idx} [{f.severity.value}] {f.title}</b> ({f.file_path}:{f.line_number})</summary>")
            lines.append("")
            lines.append(f"**Description:** {f.description}")
            if f.snippet:
                lines.append(f"```\n{f.snippet}\n```")
            lines.append(f"**Remediation:** {f.remediation}")
            if f.suggested_fix:
                lines.append(f"**Suggested Fix:**\n```python\n{f.suggested_fix}\n```")
            lines.append("</details>")
            lines.append("")

        if report.patches:
            lines.append("### 🛠️ Autonomous Patches Generated")
            lines.append(f"Generated `{len(report.patches)}` unified patch(es) ready to be applied.")

        return "\n".join(lines)
