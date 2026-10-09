"""
Unit tests for GitGhost PatchGenerator.
Copyright 2026 EvoderDev. Licensed under the Apache License, Version 2.0.
"""

import os
import tempfile
from gitghost.engine.patch_generator import PatchGenerator
from gitghost.models import Category, Finding, Severity


def test_fix_line_subprocess_shell():
    finding = Finding(
        file_path="app.py",
        line_number=1,
        severity=Severity.CRITICAL,
        category=Category.OWASP_RCE,
        rule_id="GHOST-RCE-003",
        title="Command Injection",
        description="",
        snippet="",
        remediation="",
    )
    line = '    subprocess.run("cmd", shell=True)'
    fixed = PatchGenerator.fix_line(line, finding)
    assert fixed == '    subprocess.run("cmd", shell=False)'


def test_fix_line_yaml_load():
    finding = Finding(
        file_path="config.py",
        line_number=1,
        severity=Severity.HIGH,
        category=Category.OWASP_DESERIALIZATION,
        rule_id="GHOST-DESER-002",
        title="Unsafe YAML",
        description="",
        snippet="",
        remediation="",
    )
    line = "data = yaml.load(content)"
    fixed = PatchGenerator.fix_line(line, finding)
    assert fixed == "data = yaml.safe_load(content)"


def test_fix_line_weak_hash():
    finding = Finding(
        file_path="auth.py",
        line_number=1,
        severity=Severity.MEDIUM,
        category=Category.OWASP_CRYPTO,
        rule_id="GHOST-CRYPTO-001",
        title="Weak Hash",
        description="",
        snippet="",
        remediation="",
    )
    line = "token = hashlib.md5(b'test').hexdigest()"
    fixed = PatchGenerator.fix_line(line, finding)
    assert "hashlib.sha256" in fixed


def test_generate_and_apply_patch():
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = os.path.join(tmpdir, "service.py")
        original_code = (
            "import yaml\n"
            "\n"
            "def parse_conf(txt):\n"
            "    return yaml.load(txt)\n"
        )
        with open(test_file, "w", encoding="utf-8") as f:
            f.write(original_code)

        finding = Finding(
            file_path="service.py",
            line_number=4,
            severity=Severity.HIGH,
            category=Category.OWASP_DESERIALIZATION,
            rule_id="GHOST-DESER-002",
            title="Unsafe YAML",
            description="",
            snippet="return yaml.load(txt)",
            remediation="",
        )

        patcher = PatchGenerator()
        proposal = patcher.generate_patch_for_file("service.py", [finding], base_dir=tmpdir)

        assert proposal is not None
        assert "yaml.safe_load" in proposal.patched_content
        assert "--- a/service.py" in proposal.unified_diff

        # Apply patch
        success = PatchGenerator.apply_patch(proposal, base_dir=tmpdir, backup=True)
        assert success

        # Verify applied content
        with open(test_file, "r", encoding="utf-8") as f:
            updated = f.read()
        assert "yaml.safe_load(txt)" in updated
        assert os.path.exists(f"{test_file}.bak")
