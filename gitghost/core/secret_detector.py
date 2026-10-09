"""
High-Entropy and Regex Secret & Credential Detector.
Copyright 2026 EvoderDev. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import math
import re
from typing import Dict, List, Optional, Tuple

from gitghost.models import Category, Finding, Severity


class SecretPattern:
    def __init__(
        self,
        rule_id: str,
        name: str,
        pattern: str,
        severity: Severity = Severity.CRITICAL,
        cwe: str = "CWE-798",
        min_entropy: float = 0.0,
    ):
        self.rule_id = rule_id
        self.name = name
        self.regex = re.compile(pattern, re.IGNORECASE if "generic" in rule_id else 0)
        self.severity = severity
        self.cwe = cwe
        self.min_entropy = min_entropy


class SecretDetector:
    """Detects leaked credentials, API tokens, and private keys using regex & entropy."""

    FALSE_POSITIVE_INDICATORS = {
        "example", "sample", "test", "dummy", "placeholder", "changeme",
        "fake", "mock", "none", "null", "undefined", "your_token_here",
        "your_key_here", "insert_here", "123456", "xxxxxx", "<key>",
        "${", "process.env", "os.environ", "getenv", "config.get"
    }

    PATTERNS: List[SecretPattern] = [
        SecretPattern(
            rule_id="GHOST-SEC-001",
            name="GitHub Personal Access Token",
            pattern=r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}|github_pat_[0-9a-zA-Z_]{82}",
            severity=Severity.CRITICAL,
            cwe="CWE-798",
        ),
        SecretPattern(
            rule_id="GHOST-SEC-002",
            name="AWS Access Key ID",
            pattern=r"\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b",
            severity=Severity.HIGH,
            cwe="CWE-798",
        ),
        SecretPattern(
            rule_id="GHOST-SEC-003",
            name="AWS Secret Access Key",
            pattern=r"(?i)aws_secret_access_key\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]",
            severity=Severity.CRITICAL,
            cwe="CWE-798",
            min_entropy=4.2,
        ),
        SecretPattern(
            rule_id="GHOST-SEC-004",
            name="OpenAI API Key",
            pattern=r"\b(sk-[a-zA-Z0-9]{20,}|sk-proj-[a-zA-Z0-9_-]{20,})\b",
            severity=Severity.CRITICAL,
            cwe="CWE-798",
        ),
        SecretPattern(
            rule_id="GHOST-SEC-005",
            name="Anthropic Claude API Key",
            pattern=r"\b(sk-ant-api03-[a-zA-Z0-9_-]{80,})\b",
            severity=Severity.CRITICAL,
            cwe="CWE-798",
        ),
        SecretPattern(
            rule_id="GHOST-SEC-006",
            name="Google API / Gemini Key",
            pattern=r"\b(AIza[0-9A-Za-z\-_]{35})\b",
            severity=Severity.CRITICAL,
            cwe="CWE-798",
        ),
        SecretPattern(
            rule_id="GHOST-SEC-007",
            name="Slack Token / Webhook",
            pattern=r"(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9\-]*|https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+)",
            severity=Severity.HIGH,
            cwe="CWE-798",
        ),
        SecretPattern(
            rule_id="GHOST-SEC-008",
            name="Private Encryption Key",
            pattern=r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP)? PRIVATE KEY-----",
            severity=Severity.CRITICAL,
            cwe="CWE-312",
        ),
        SecretPattern(
            rule_id="GHOST-SEC-009",
            name="Database Connection String with Credentials",
            pattern=r"(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis)://[a-zA-Z0-9_\-\.]+:[^@\s\"'\<\>]+@[a-zA-Z0-9_\-\.]+",
            severity=Severity.CRITICAL,
            cwe="CWE-312",
        ),
        SecretPattern(
            rule_id="GHOST-SEC-010",
            name="Stripe Live Secret Key",
            pattern=r"\b(sk_live_[0-9a-zA-Z]{24,})\b",
            severity=Severity.CRITICAL,
            cwe="CWE-798",
        ),
        SecretPattern(
            rule_id="GHOST-SEC-011",
            name="Generic High-Entropy Secret / Token Assignment",
            pattern=r"""(?i)(?:api[_-]?key|secret[_-]?key|client[_-]?secret|auth[_-]?token|access[_-]?token|private[_-]?key|db[_-]?password|password|passwd)\s*[:=]\s*["']([^"'\s]{10,})["']""",
            severity=Severity.HIGH,
            cwe="CWE-798",
            min_entropy=3.8,
        ),
    ]

    EXACT_DUMMY_VALUES = {
        "your_token_here", "your_key_here", "dummy_token", "sample_test_value",
        "placeholder", "changeme", "fake_token", "insert_here", "xxxxxx",
        "123456", "12345678", "<key>", "<your_key>", "none", "null", "undefined"
    }

    @staticmethod
    def calculate_shannon_entropy(data: str) -> float:
        """Calculates the Shannon entropy of a string."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        frequencies: Dict[str, int] = {}
        for char in data:
            frequencies[char] = frequencies.get(char, 0) + 1
        for count in frequencies.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        return entropy

    @staticmethod
    def mask_secret(secret: str) -> str:
        """Masks a sensitive string preserving prefix and suffix for reference."""
        if len(secret) <= 8:
            return "********"
        prefix = secret[:8] if len(secret) >= 16 else secret[:4]
        suffix = secret[-4:]
        return f"{prefix}****{suffix}"

    def is_false_positive(self, matched_text: str, context_line: str) -> bool:
        """Determines if a match is an obvious dummy value, test placeholder, or env var."""
        lower_match = matched_text.lower().strip("\"' ")
        lower_line = context_line.lower()

        for env_marker in ("os.environ", "process.env", "getenv(", "config.get(", "${"):
            if env_marker in lower_line:
                return True

        if lower_match in self.EXACT_DUMMY_VALUES:
            return True

        for prefix in ("your_", "insert_", "dummy_", "fake_", "mock_", "sample_"):
            if lower_match.startswith(prefix):
                return True

        if len(set(lower_match)) <= 3 and len(lower_match) > 8:
            return True

        return False

    def scan_line(
        self,
        file_path: str,
        line_number: int,
        line_content: str,
    ) -> List[Finding]:
        """Scans a single line of code or diff addition for secret leaks."""
        findings: List[Finding] = []

        for p in self.PATTERNS:
            for match in p.regex.finditer(line_content):
                # Retrieve actual captured group if present
                matched_secret = match.group(1) if match.groups() else match.group(0)
                if not matched_secret:
                    continue

                if self.is_false_positive(matched_secret, line_content):
                    continue

                if p.min_entropy > 0.0:
                    entropy = self.calculate_shannon_entropy(matched_secret)
                    if entropy < p.min_entropy:
                        continue

                masked = self.mask_secret(matched_secret)
                start_col = match.start() + 1

                finding = Finding(
                    file_path=file_path,
                    line_number=line_number,
                    column=start_col,
                    severity=p.severity,
                    category=Category.SECRET_LEAK,
                    rule_id=p.rule_id,
                    title=f"Hardcoded {p.name} Exposed",
                    description=(
                        f"Detected hardcoded secret ({p.name}) in source code: '{masked}'. "
                        "Committing plaintext secrets risks unauthorized access and credential leakage."
                    ),
                    snippet=line_content.strip(),
                    remediation=(
                        "Immediately revoke and rotate this credential. Move the secret to environment "
                        "variables, AWS Secrets Manager, GitHub Secrets, or HashiCorp Vault. Use "
                        "os.environ.get(...) to read at runtime."
                    ),
                    suggested_fix=(
                        f"# Replace hardcoded secret with environment variable:\n"
                        f"import os\n"
                        f"SECRET_VALUE = os.environ.get('YOUR_SECRET_ENV_VAR')"
                    ),
                    cwe=p.cwe,
                    owasp_tag="A02:2021-Cryptographic Failures",
                )
                findings.append(finding)

        # Deduplicate: if a specific high-confidence rule matched, drop redundant generic findings
        if any(f.rule_id != "GHOST-SEC-011" for f in findings):
            findings = [f for f in findings if f.rule_id != "GHOST-SEC-011"]

        return findings

    def scan_diff_file(self, diff_file) -> List[Finding]:
        """Scans all additions in a parsed DiffFile for leaked secrets."""
        findings: List[Finding] = []
        target_path = diff_file.target_path

        for hunk in diff_file.hunks:
            for line in hunk.lines:
                if line.is_addition and line.new_line_no is not None:
                    line_findings = self.scan_line(
                        file_path=target_path,
                        line_number=line.new_line_no,
                        line_content=line.content,
                    )
                    findings.extend(line_findings)

        return findings

    def scan_text(self, file_path: str, text: str) -> List[Finding]:
        """Scans an entire file's text line-by-line."""
        findings: List[Finding] = []
        lines = text.splitlines()
        for idx, line in enumerate(lines, start=1):
            findings.extend(self.scan_line(file_path, idx, line))
        return findings
