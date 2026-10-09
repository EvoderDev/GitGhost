"""
Unit tests for GitGhost ReviewAgent.
Copyright 2026 EvoderDev. Licensed under the Apache License, Version 2.0.
"""

from gitghost.engine.review_agent import OfflineRuleAgent, ReviewAgent
from gitghost.models import Category, Finding, Severity


def test_review_agent_offline_clean():
    agent = ReviewAgent(provider_name="offline")
    review = agent.review(diff_files=[], findings=[], raw_diff="")

    assert review["risk_score"] == 0
    assert review["agent_status"] == "PASS"


def test_review_agent_offline_with_findings():
    agent = ReviewAgent(provider_name="offline")
    findings = [
        Finding(
            file_path="config.py",
            line_number=10,
            severity=Severity.CRITICAL,
            category=Category.SECRET_LEAK,
            rule_id="GHOST-SEC-001",
            title="Leaked GitHub PAT",
            description="",
            snippet="",
            remediation="",
        ),
        Finding(
            file_path="runner.py",
            line_number=20,
            severity=Severity.HIGH,
            category=Category.OWASP_RCE,
            rule_id="GHOST-RCE-002",
            title="Command Injection",
            description="",
            snippet="",
            remediation="",
        ),
    ]

    review = agent.review(diff_files=[], findings=findings, raw_diff="")

    assert review["risk_score"] >= 50
    assert review["agent_status"] == "BLOCKED"
    assert len(review["recommendations"]) == 2
