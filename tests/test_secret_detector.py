"""
Unit tests for GitGhost SecretDetector.
Copyright 2026 EvoderDev. Licensed under the Apache License, Version 2.0.
"""

from gitghost.core.secret_detector import SecretDetector
from gitghost.models import Category, Severity


def test_secret_detector_github_pat():
    detector = SecretDetector()
    line = 'GITHUB_TOKEN = "ghp_111122223333444455556666777788889999"'
    findings = detector.scan_line("config.py", 12, line)

    assert len(findings) == 1
    f = findings[0]
    assert f.category == Category.SECRET_LEAK
    assert f.severity == Severity.CRITICAL
    assert f.rule_id == "GHOST-SEC-001"
    assert "ghp_1111****9999" in f.description


def test_secret_detector_openai_key():
    detector = SecretDetector()
    line = 'client = OpenAI(api_key="sk-1234567890abcdef1234567890abcdef")'
    findings = detector.scan_line("ai_service.py", 5, line)

    assert len(findings) == 1
    assert findings[0].rule_id == "GHOST-SEC-004"
    assert findings[0].severity == Severity.CRITICAL


def test_secret_detector_aws_keys():
    detector = SecretDetector()
    line = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'
    findings = detector.scan_line("aws.py", 1, line)

    assert len(findings) == 1
    assert findings[0].rule_id == "GHOST-SEC-002"
    assert findings[0].severity == Severity.HIGH


def test_secret_detector_private_key():
    detector = SecretDetector()
    line = "-----BEGIN RSA PRIVATE KEY-----"
    findings = detector.scan_line("id_rsa", 1, line)

    assert len(findings) == 1
    assert findings[0].rule_id == "GHOST-SEC-008"


def test_secret_detector_false_positive_filtering():
    detector = SecretDetector()
    placeholders = [
        'API_KEY = "your_key_here"',
        'TOKEN = "dummy_token_123456"',
        'KEY = "sample_test_value"',
        'token = os.environ.get("MY_TOKEN")',
        'key = "${API_KEY}"',
    ]
    for line in placeholders:
        findings = detector.scan_line("test.py", 1, line)
        assert len(findings) == 0, f"False positive triggered on: {line}"


def test_shannon_entropy():
    # Low entropy (repeated or simple characters)
    low = SecretDetector.calculate_shannon_entropy("aaaaaaaaaaaa")
    assert low < 1.0

    # High entropy (random base64/hex token)
    high = SecretDetector.calculate_shannon_entropy("q9Xy8Z!pL2m$0A7v")
    assert high > 3.5
