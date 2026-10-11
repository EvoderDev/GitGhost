"""
Autonomous Unified Patch Generator and Auto-Remediation Engine.
Copyright 2026 EvoderDev. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import difflib
import os
import re
import shutil
from typing import Dict, List, Optional, Tuple

from gitghost.models import Category, Finding, PatchProposal, Severity


class PatchGenerator:
    """Generates standard unified diff patches and applies automated security fixes."""

    @staticmethod
    def fix_line(line: str, finding: Finding) -> Optional[str]:
        """Applies rule-specific deterministic code remediation to a line."""
        original = line

        # 1. Command Injection: subprocess with shell=True
        if finding.rule_id == "GHOST-RCE-003":
            if "shell=True" in line:
                fixed = line.replace("shell=True", "shell=False")
                return fixed

        # 2. Command Injection: os.system(cmd)
        if finding.rule_id == "GHOST-RCE-002":
            match = re.search(r"os\.system\((.*?)\)", line)
            if match:
                cmd_expr = match.group(1).strip()
                indent = " " * (len(line) - len(line.lstrip()))
                return f"{indent}import shlex, subprocess\n{indent}subprocess.run(shlex.split({cmd_expr}), check=True)"

        # 3. Dynamic Code Execution: eval()
        if finding.rule_id == "GHOST-RCE-001":
            if "eval(" in line:
                return line.replace("eval(", "ast.literal_eval(")

        # 4. Insecure Deserialization: yaml.load
        if finding.rule_id == "GHOST-DESER-002":
            if "yaml.load(" in line:
                return re.sub(r"yaml\.load\(([^,)]+)(?:,[^)]+)?\)", r"yaml.safe_load(\1)", line)

        # 5. Insecure Deserialization: pickle.loads
        if finding.rule_id == "GHOST-DESER-001":
            if "pickle.loads(" in line:
                return line.replace("pickle.loads(", "json.loads(")

        # 6. Weak Cryptography: hashlib.md5 or hashlib.sha1
        if finding.rule_id == "GHOST-CRYPTO-001":
            if "hashlib.md5(" in line:
                return line.replace("hashlib.md5(", "hashlib.sha256(")
            elif "hashlib.sha1(" in line:
                return line.replace("hashlib.sha1(", "hashlib.sha256(")

        # 7. SQL Injection query concatenation
        if finding.rule_id == "GHOST-SQL-001":
            # Match cursor.execute(f"SELECT ... {var}")
            f_match = re.search(r'cursor\.execute\(f["\'](.*?)\{([a-zA-Z0-9_]+)\}(.*?)["\']\)', line)
            if f_match:
                prefix, var, suffix = f_match.groups()
                indent = " " * (len(line) - len(line.lstrip()))
                return f'{indent}cursor.execute("{prefix}%s{suffix}", ({var},))'

        # 8. Secret Leak: replace hardcoded value with os.environ.get
        if finding.category == Category.SECRET_LEAK:
            # Pattern: KEY = "secret_val"
            assign_match = re.search(r'([A-Za-z0-9_]+)\s*=\s*["\']([^"\']+)["\']', line)
            if assign_match:
                var_name, _ = assign_match.groups()
                env_name = var_name.upper()
                indent = " " * (len(line) - len(line.lstrip()))
                return f'{indent}import os\n{indent}{var_name} = os.environ.get("{env_name}")'

        # 9. Performance: time.sleep in async def
        if finding.rule_id == "GHOST-PERF-002":
            if "time.sleep(" in line:
                indent = " " * (len(line) - len(line.lstrip()))
                return f"{indent}import asyncio\n{indent}await asyncio.sleep({line.split('time.sleep(')[1].split(')')[0]})"

        # 10. Path Traversal: validate path with os.path.basename / abspath
        if finding.rule_id == "GHOST-PATH-001":
            match = re.search(r"open\((.*?)\)", line)
            if match:
                path_arg = match.group(1).split(",")[0].strip()
                indent = " " * (len(line) - len(line.lstrip()))
                rest = line[match.end():]
                fixed_call = f"open(os.path.abspath({path_arg})"
                if "," in match.group(1):
                    fixed_call += "," + ",".join(match.group(1).split(",")[1:])
                fixed_call += ")"
                return f"{indent}import os\n{line[:match.start()]}{fixed_call}{rest}"

        # 11. Unclosed Resources: convert f = open(...) to with open(...) as f:
        if finding.rule_id == "GHOST-RES-001":
            match = re.search(r"([A-Za-z0-9_]+)\s*=\s*open\((.*?)\)", line)
            if match:
                var_name, open_args = match.groups()
                indent = " " * (len(line) - len(line.lstrip()))
                return f"{indent}with open({open_args}) as {var_name}:"

        return None

    def generate_patch_for_file(
        self,
        file_path: str,
        findings: List[Finding],
        base_dir: str = ".",
    ) -> Optional[PatchProposal]:
        """Generates unified diff patch for a single file addressing its findings."""
        target_path = os.path.join(base_dir, file_path) if not os.path.isabs(file_path) else file_path
        if not os.path.exists(target_path) or not os.path.isfile(target_path):
            return None

        with open(target_path, "r", encoding="utf-8", errors="replace") as f:
            original_content = f.read()

        lines = original_content.splitlines(keepends=True)
        modified_lines = list(lines)
        addressed_findings: List[str] = []

        # Sort findings by line number descending so multi-line additions don't offset earlier lines
        sorted_findings = sorted(findings, key=lambda x: x.line_number, reverse=True)

        for finding in sorted_findings:
            idx = finding.line_number - 1
            if 0 <= idx < len(modified_lines):
                orig_line = modified_lines[idx].rstrip("\r\n")
                fixed = self.fix_line(orig_line, finding)
                if fixed and fixed != orig_line:
                    # Preserve original newline style
                    nl = "\r\n" if modified_lines[idx].endswith("\r\n") else "\n"
                    modified_lines[idx] = fixed + nl
                    addressed_findings.append(finding.id)

        if not addressed_findings:
            return None

        patched_content = "".join(modified_lines)
        unified_diff_lines = list(
            difflib.unified_diff(
                lines,
                modified_lines,
                fromfile=f"a/{file_path}",
                tofile=f"b/{file_path}",
                lineterm="",
            )
        )
        unified_diff = "\n".join(unified_diff_lines)

        return PatchProposal(
            file_path=file_path,
            original_content=original_content,
            patched_content=patched_content,
            unified_diff=unified_diff,
            findings_addressed=addressed_findings,
            rationale=f"Autonomously mitigated {len(addressed_findings)} security/performance finding(s).",
        )

    def generate_all_patches(
        self,
        findings: List[Finding],
        base_dir: str = ".",
    ) -> List[PatchProposal]:
        """Generates patches grouped by file for all reported findings."""
        findings_by_file: Dict[str, List[Finding]] = {}
        for f in findings:
            findings_by_file.setdefault(f.file_path, []).append(f)

        proposals: List[PatchProposal] = []
        for file_path, file_findings in findings_by_file.items():
            patch = self.generate_patch_for_file(file_path, file_findings, base_dir=base_dir)
            if patch:
                proposals.append(patch)

        return proposals

    @staticmethod
    def apply_patch(patch: PatchProposal, base_dir: str = ".", backup: bool = True) -> bool:
        """Applies a PatchProposal to the filesystem with optional backup."""
        if not patch.patched_content:
            return False

        full_path = os.path.join(base_dir, patch.file_path) if not os.path.isabs(patch.file_path) else patch.file_path
        if not os.path.exists(full_path):
            return False

        if backup:
            backup_path = f"{full_path}.bak"
            shutil.copy2(full_path, backup_path)

        with open(full_path, "w", encoding="utf-8") as f:
            f.write(patch.patched_content)

        return True
