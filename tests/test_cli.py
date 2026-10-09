"""
Unit tests for GitGhost CLI.
Copyright 2026 EvoderDev. Licensed under the Apache License, Version 2.0.
"""

import json
import os
import tempfile
from click.testing import CliRunner
from gitghost.cli import cli


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "GitGhost" in result.output
    assert "scan" in result.output
    assert "fix" in result.output
    assert "review" in result.output


def test_cli_scan_clean_file():
    runner = CliRunner()
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write("def safe_func():\n    return 42\n")
        path = f.name

    try:
        result = runner.invoke(cli, ["scan", "--file", path, "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["passed"] is True
        assert len(data["findings"]) == 0
    finally:
        os.remove(path)


def test_cli_scan_vulnerable_file():
    runner = CliRunner()
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write("import os\n\ndef run(cmd):\n    os.system(cmd)\n")
        path = f.name

    try:
        result = runner.invoke(cli, ["scan", "--file", path, "--format", "json"])
        # Should exit with 1 because fail-on defaults to high and os.system is CRITICAL
        assert result.exit_code == 1
        data = json.loads(result.output)
        assert data["passed"] is False
        assert len(data["findings"]) >= 1
        assert data["findings"][0]["rule_id"] == "GHOST-RCE-002"
    finally:
        os.remove(path)


def test_cli_scan_sarif_format():
    runner = CliRunner()
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write("token = 'ghp_111122223333444455556666777788889999'\n")
        path = f.name

    try:
        result = runner.invoke(cli, ["scan", "--file", path, "--format", "sarif"])
        assert "runs" in result.output
        sarif = json.loads(result.output)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) >= 1
    finally:
        os.remove(path)
