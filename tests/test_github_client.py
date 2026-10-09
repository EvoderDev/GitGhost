"""
Unit tests for GitGhost GitHub Client & Integrators.
Copyright 2026 EvoderDev. Licensed under the Apache License, Version 2.0.
"""

from gitghost.integrators.github_client import GitHubClient
from gitghost.models import Category, Finding, ScanReport, Severity


def test_github_client_unconfigured():
    client = GitHubClient(token="", repository="")
    assert not client.is_configured


def test_github_client_configured():
    client = GitHubClient(token="mock_token", repository="EvoderDev/GitGhost")
    assert client.is_configured
    assert client.headers["Authorization"] == "Bearer mock_token"


def test_format_markdown_summary():
    client = GitHubClient()
    report = ScanReport(scanned_files_count=3)
    report.findings.append(
        Finding(
            file_path="src/auth.py",
            line_number=45,
            severity=Severity.CRITICAL,
            category=Category.SECRET_LEAK,
            rule_id="GHOST-SEC-001",
            title="Exposed GitHub PAT",
            description="Leaked credential in repository",
            snippet='TOKEN = "ghp_..."',
            remediation="Rotate token immediately",
        )
    )
    report.calculate_metrics()

    md = client.format_markdown_summary(report)
    assert "# 👻 GitGhost Security & Quality Report" in md
    assert "Exposed GitHub PAT" in md
    assert "`src/auth.py:45`" in md
    assert "🔴 **BLOCK**" in md
