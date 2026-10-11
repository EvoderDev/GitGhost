"""
Deep Abstract Syntax Tree (AST) & Semantic Code Vulnerability Scanner.
Copyright 2026 EvoderDev. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import ast
import os
import re
from typing import Any, List, Optional, Set

from gitghost.models import Category, Finding, Severity


class PythonASTVisitor(ast.NodeVisitor):
    """Inspects Python AST for OWASP vulnerabilities and performance flaws."""

    def __init__(self, file_path: str, code_lines: List[str], rules_config: Optional[dict] = None):
        super().__init__()
        self.file_path = file_path
        self.code_lines = code_lines
        self.rules_config = rules_config or {}
        self.findings: List[Finding] = []
        self.in_loop: bool = False
        self.in_with: bool = False
        self.current_function: Optional[ast.FunctionDef | ast.AsyncFunctionDef] = None

    def _is_rule_enabled(self, rule_name: str) -> bool:
        return self.rules_config.get(rule_name, True)

    def _get_snippet(self, node: ast.AST) -> str:
        lineno = getattr(node, "lineno", 1)
        if 1 <= lineno <= len(self.code_lines):
            return self.code_lines[lineno - 1].strip()
        return ""

    def visit_With(self, node: ast.With) -> None:
        prev_with = self.in_with
        self.in_with = True
        self.generic_visit(node)
        self.in_with = prev_with

    def visit_Assign(self, node: ast.Assign) -> None:
        # Check unclosed resource: f = open(...) without with statement
        if not self.in_with and self._is_rule_enabled("unclosed_resources"):
            if isinstance(node.value, ast.Call):
                func = node.value.func
                is_open = False
                if isinstance(func, ast.Name) and func.id == "open":
                    is_open = True
                elif isinstance(func, ast.Attribute) and func.attr == "open":
                    is_open = True
                if is_open:
                    self.findings.append(
                        Finding(
                            file_path=self.file_path,
                            line_number=node.lineno,
                            column=node.col_offset + 1,
                            severity=Severity.LOW,
                            category=Category.CODE_SMELL,
                            rule_id="GHOST-RES-001",
                            title="Unclosed File Resource Leak",
                            description=(
                                "File handle opened via 'open()' assignment without a 'with' context manager. "
                                "This risks leaking file descriptors if exceptions occur before explicit close()."
                            ),
                            snippet=self._get_snippet(node),
                            remediation="Use a 'with open(...) as handle:' context manager block.",
                            suggested_fix="with open(...) as f:\n    data = f.read()",
                            cwe="CWE-775",
                            owasp_tag="A04:2021-Insecure Design",
                        )
                    )
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        prev_loop = self.in_loop
        self.in_loop = True
        self.generic_visit(node)
        self.in_loop = prev_loop

    def visit_While(self, node: ast.While) -> None:
        prev_loop = self.in_loop
        self.in_loop = True
        self.generic_visit(node)
        self.in_loop = prev_loop

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        prev_func = self.current_function
        self.current_function = node
        self.generic_visit(node)
        self.current_function = prev_func

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        prev_func = self.current_function
        self.current_function = node
        self.generic_visit(node)
        self.current_function = prev_func

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        # Performance: Quadratic string concatenation inside loop (s += chunk)
        if self.in_loop and isinstance(node.op, ast.Add):
            if isinstance(node.target, ast.Name):
                is_string_concat = False
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    is_string_concat = True
                elif isinstance(node.value, ast.JoinedStr):
                    is_string_concat = True
                elif isinstance(node.value, ast.Call):
                    if isinstance(node.value.func, ast.Name) and node.value.func.id == "str":
                        is_string_concat = True
                    elif isinstance(node.value.func, ast.Attribute) and node.value.func.attr in ("format", "decode"):
                        is_string_concat = True

                if is_string_concat:
                    self.findings.append(
                        Finding(
                            file_path=self.file_path,
                            line_number=node.lineno,
                            column=node.col_offset + 1,
                            severity=Severity.MEDIUM,
                            category=Category.PERFORMANCE,
                            rule_id="GHOST-PERF-001",
                            title="Quadratic String Concatenation in Loop",
                            description=(
                                f"Repeatedly appending strings to variable '{node.target.id}' inside a loop "
                                "causes quadratic O(N^2) memory reallocation. In large iterations, this creates severe performance bottlenecks."
                            ),
                            snippet=self._get_snippet(node),
                            remediation="Collect chunks in a list and combine with ''.join(chunks).",
                            suggested_fix=f"# Optimized pattern:\nchunks = []\n# inside loop: chunks.append(item)\nresult = ''.join(chunks)",
                            cwe="CWE-400",
                        )
                    )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        func_name = ""
        full_call_str = ""

        if isinstance(func, ast.Name):
            func_name = func.id
            full_call_str = func.id
        elif isinstance(func, ast.Attribute):
            func_name = func.attr
            if isinstance(func.value, ast.Name):
                full_call_str = f"{func.value.id}.{func.attr}"
            elif isinstance(func.value, ast.Attribute):
                full_call_str = f"...{func.value.attr}.{func.attr}"
            else:
                full_call_str = func.attr

        # 1. RCE: eval() / exec()
        if func_name in ("eval", "exec"):
            self.findings.append(
                Finding(
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset + 1,
                    severity=Severity.CRITICAL,
                    category=Category.OWASP_RCE,
                    rule_id="GHOST-RCE-001",
                    title=f"Dynamic Code Execution via {func_name}()",
                    description=(
                        f"Direct invocation of '{func_name}()' executes arbitrary code strings. "
                        "If user input reaches this call, attackers gain full Remote Code Execution (RCE)."
                    ),
                    snippet=self._get_snippet(node),
                    remediation="Eliminate eval/exec. Use ast.literal_eval() for data literals or safe parsers (json, yaml).",
                    suggested_fix="import ast\nsafe_data = ast.literal_eval(untrusted_str)",
                    cwe="CWE-94",
                    owasp_tag="A03:2021-Injection",
                )
            )

        # 2. RCE / Command Injection: os.system
        if full_call_str in ("os.system", "posix.system"):
            self.findings.append(
                Finding(
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset + 1,
                    severity=Severity.CRITICAL,
                    category=Category.OWASP_RCE,
                    rule_id="GHOST-RCE-002",
                    title="Command Injection via os.system()",
                    description=(
                        "os.system() spawns a system shell command string directly. "
                        "Unsanitized input allows shell metacharacters (; && | `) to execute arbitrary commands."
                    ),
                    snippet=self._get_snippet(node),
                    remediation="Use subprocess.run(['cmd', arg1], shell=False) with parameterized arguments.",
                    suggested_fix="import subprocess\nsubprocess.run(['command', arg1, arg2], check=True)",
                    cwe="CWE-78",
                    owasp_tag="A03:2021-Injection",
                )
            )

        # 3. RCE: subprocess with shell=True
        if func_name in ("run", "Popen", "call", "check_call", "check_output"):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.findings.append(
                        Finding(
                            file_path=self.file_path,
                            line_number=node.lineno,
                            column=node.col_offset + 1,
                            severity=Severity.CRITICAL,
                            category=Category.OWASP_RCE,
                            rule_id="GHOST-RCE-003",
                            title="Command Injection via subprocess with shell=True",
                            description=(
                                f"Invocation of '{full_call_str}' with 'shell=True' opens a subshell command interpreter. "
                                "This enables command chaining and arbitrary shell injection."
                            ),
                            snippet=self._get_snippet(node),
                            remediation="Set shell=False and pass arguments as an explicit list, or use shlex.split().",
                            suggested_fix="import shlex, subprocess\nsubprocess.run(shlex.split(command), shell=False, check=True)",
                            cwe="CWE-78",
                            owasp_tag="A03:2021-Injection",
                        )
                    )

        # 4. SQL Injection: cursor.execute / db.session.execute with formatted queries
        if func_name in ("execute", "executemany", "raw"):
            if node.args:
                first_arg = node.args[0]
                # Check if first arg is an f-string (JoinedStr), formatted string, or string concatenation (+)
                is_sqli_prone = False
                if isinstance(first_arg, ast.JoinedStr):
                    is_sqli_prone = True
                elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, (ast.Add, ast.Mod)):
                    is_sqli_prone = True
                elif isinstance(first_arg, ast.Call) and isinstance(first_arg.func, ast.Attribute) and first_arg.func.attr == "format":
                    is_sqli_prone = True

                if is_sqli_prone:
                    self.findings.append(
                        Finding(
                            file_path=self.file_path,
                            line_number=node.lineno,
                            column=node.col_offset + 1,
                            severity=Severity.CRITICAL,
                            category=Category.OWASP_SQLI,
                            rule_id="GHOST-SQL-001",
                            title="SQL Injection Vulnerability via Query String Interpolation",
                            description=(
                                f"SQL execution method '{func_name}' received a dynamically constructed query "
                                "via string concatenation or formatting. Attackers can bypass authentication or exfiltrate database data."
                            ),
                            snippet=self._get_snippet(node),
                            remediation="Use parameterized queries with placeholders (%s, ?, :param) and bind variables.",
                            suggested_fix="cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
                            cwe="CWE-89",
                            owasp_tag="A03:2021-Injection",
                        )
                    )

        # 5. Insecure Deserialization: pickle.loads / pickle.load
        if full_call_str in ("pickle.loads", "pickle.load", "_pickle.loads", "_pickle.load"):
            self.findings.append(
                Finding(
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset + 1,
                    severity=Severity.HIGH,
                    category=Category.OWASP_DESERIALIZATION,
                    rule_id="GHOST-DESER-001",
                    title="Insecure Deserialization via pickle",
                    description=(
                        f"Invocation of '{full_call_str}' deserializes arbitrary Python bytecode. "
                        "Crafted pickle payloads execute code instantly upon unpickling via __reduce__."
                    ),
                    snippet=self._get_snippet(node),
                    remediation="Never unpickle untrusted data. Use secure serialization formats like JSON, MessagePack, or Protocol Buffers.",
                    suggested_fix="import json\ndata = json.loads(payload)",
                    cwe="CWE-502",
                    owasp_tag="A08:2021-Software and Data Integrity Failures",
                )
            )

        # 6. Insecure Deserialization: yaml.load without SafeLoader
        if full_call_str in ("yaml.load",):
            has_safe_loader = False
            for kw in node.keywords:
                if kw.arg == "Loader":
                    if isinstance(kw.value, ast.Attribute) and "Safe" in kw.value.attr:
                        has_safe_loader = True
                    elif isinstance(kw.value, ast.Name) and "Safe" in kw.value.id:
                        has_safe_loader = True
            if not has_safe_loader:
                self.findings.append(
                    Finding(
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset + 1,
                        severity=Severity.HIGH,
                        category=Category.OWASP_DESERIALIZATION,
                        rule_id="GHOST-DESER-002",
                        title="Unsafe YAML Loading (yaml.load)",
                        description=(
                            "yaml.load() without SafeLoader can construct arbitrary Python objects and trigger remote code execution."
                        ),
                        snippet=self._get_snippet(node),
                        remediation="Use yaml.safe_load(data) instead of yaml.load().",
                        suggested_fix="import yaml\ndata = yaml.safe_load(content)",
                        cwe="CWE-502",
                        owasp_tag="A08:2021-Software and Data Integrity Failures",
                    )
                )

        # 7. Weak Cryptography: hashlib.md5 or hashlib.sha1
        if full_call_str in ("hashlib.md5", "hashlib.sha1"):
            self.findings.append(
                Finding(
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset + 1,
                    severity=Severity.MEDIUM,
                    category=Category.OWASP_CRYPTO,
                    rule_id="GHOST-CRYPTO-001",
                    title=f"Weak Cryptographic Hash Algorithm ({func_name})",
                    description=(
                        f"Algorithm '{func_name}' is cryptographically broken and vulnerable to collision and preimage attacks. "
                        "Do not use MD5/SHA1 for digital signatures, password hashing, or integrity verification."
                    ),
                    snippet=self._get_snippet(node),
                    remediation="Upgrade to hashlib.sha256() or SHA-3, or bcrypt/argon2 for password hashing.",
                    suggested_fix="import hashlib\nhash_obj = hashlib.sha256(data)",
                    cwe="CWE-327",
                    owasp_tag="A02:2021-Cryptographic Failures",
                )
            )

        # 8. Performance: Synchronous time.sleep in async def
        if full_call_str == "time.sleep" and isinstance(self.current_function, ast.AsyncFunctionDef):
            self.findings.append(
                Finding(
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset + 1,
                    severity=Severity.HIGH,
                    category=Category.PERFORMANCE,
                    rule_id="GHOST-PERF-002",
                    title="Blocking Synchronous time.sleep() in Async Coroutine",
                    description=(
                        "Calling 'time.sleep()' inside an async coroutine freezes the entire event loop thread, "
                        "blocking all concurrent tasks and web requests from processing."
                    ),
                    snippet=self._get_snippet(node),
                    remediation="Replace with 'await asyncio.sleep(duration)' to yield control back to the event loop.",
                    suggested_fix="import asyncio\nawait asyncio.sleep(duration)",
                    cwe="CWE-400",
                )
            )

        # 9. Path Traversal: open() with dynamically concatenated or formatted paths
        if func_name == "open" and self._is_rule_enabled("path_traversal"):
            if node.args:
                first_arg = node.args[0]
                is_traversal_prone = False
                if isinstance(first_arg, (ast.JoinedStr, ast.BinOp)):
                    is_traversal_prone = True
                elif isinstance(first_arg, ast.Call) and isinstance(first_arg.func, ast.Attribute) and first_arg.func.attr == "join":
                    if any(isinstance(a, (ast.Name, ast.Call, ast.JoinedStr, ast.BinOp)) for a in first_arg.args):
                        is_traversal_prone = True

                if is_traversal_prone:
                    self.findings.append(
                        Finding(
                            file_path=self.file_path,
                            line_number=node.lineno,
                            column=node.col_offset + 1,
                            severity=Severity.HIGH,
                            category=Category.OWASP_PATH_TRAVERSAL,
                            rule_id="GHOST-PATH-001",
                            title="Path Traversal Risk via Dynamic File Open",
                            description=(
                                "File path in 'open()' is dynamically concatenated without path containment verification. "
                                "Attackers using '../' sequences can escape root boundaries and access sensitive files."
                            ),
                            snippet=self._get_snippet(node),
                            remediation="Validate paths using os.path.abspath() or sanitize with os.path.basename().",
                            suggested_fix="import os\nsafe_path = os.path.abspath(user_path)\nwith open(safe_path) as f:",
                            cwe="CWE-22",
                            owasp_tag="A01:2021-Broken Access Control",
                        )
                    )

        self.generic_visit(node)


class MultiLanguagePatternScanner:
    """Heuristic semantic pattern scanner for JavaScript/TypeScript, Go, and Shell scripts."""

    RULES = [
        # JS/TS Command Injection
        {
            "lang": [".js", ".ts", ".jsx", ".tsx", ".mjs"],
            "pattern": r"""child_process\.(?:exec|execSync)\s*\(\s*[`'"].*?\$\{""",
            "rule_id": "GHOST-JS-RCE-001",
            "title": "Command Injection in Node.js child_process",
            "severity": Severity.CRITICAL,
            "category": Category.OWASP_RCE,
            "description": "Dynamic template string passed to child_process.exec allows command chaining.",
            "remediation": "Use child_process.execFile() or spawn() with argument arrays.",
            "cwe": "CWE-78",
            "owasp_tag": "A03:2021-Injection",
        },
        # JS/TS innerHTML XSS
        {
            "lang": [".js", ".ts", ".jsx", ".tsx"],
            "pattern": r"""(?:\.innerHTML|\.outerHTML)\s*=\s*(?!['"`]<[a-zA-Z]+>['"`])""",
            "rule_id": "GHOST-JS-XSS-001",
            "title": "Cross-Site Scripting (XSS) via innerHTML Assignment",
            "severity": Severity.HIGH,
            "category": Category.OWASP_XSS,
            "description": "Direct assignment of untrusted content to innerHTML introduces Cross-Site Scripting vulnerabilities.",
            "remediation": "Use textContent or DOMPurify.sanitize().",
            "cwe": "CWE-79",
            "owasp_tag": "A03:2021-Injection",
        },
        # Go Command Injection
        {
            "lang": [".go"],
            "pattern": r"""exec\.Command\s*\(\s*"(?:sh|bash|cmd)""",
            "rule_id": "GHOST-GO-RCE-001",
            "title": "Subshell Execution in Go exec.Command",
            "severity": Severity.HIGH,
            "category": Category.OWASP_RCE,
            "description": "Invoking a shell binary ('sh', 'bash') allows shell meta-character injection.",
            "remediation": "Invoke specific binary directly without wrapping in a shell interpreter.",
            "cwe": "CWE-78",
            "owasp_tag": "A03:2021-Injection",
        },
        # Bash dangerous curl pipe to sh
        {
            "lang": [".sh", ".bash"],
            "pattern": r"""curl\s+[^\|]+\|\s*(?:bash|sh)""",
            "rule_id": "GHOST-SH-PIPE-001",
            "title": "Insecure Remote Script Execution (curl | bash)",
            "severity": Severity.HIGH,
            "category": Category.OWASP_RCE,
            "description": "Piping unverified remote web content directly into a shell interpreter poses severe MITM and supply chain risks.",
            "remediation": "Download the script, verify cryptographic checksum/signature, and review before execution.",
            "cwe": "CWE-494",
            "owasp_tag": "A08:2021-Software and Data Integrity Failures",
        },
    ]

    @classmethod
    def scan_file(cls, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        ext = os.path.splitext(file_path)[1].lower()
        lines = content.splitlines()

        for rule in cls.RULES:
            if ext in rule["lang"]:
                regex = re.compile(rule["pattern"])
                for idx, line in enumerate(lines, start=1):
                    if regex.search(line):
                        finding = Finding(
                            file_path=file_path,
                            line_number=idx,
                            severity=rule["severity"],
                            category=rule["category"],
                            rule_id=rule["rule_id"],
                            title=rule["title"],
                            description=rule["description"],
                            snippet=line.strip(),
                            remediation=rule["remediation"],
                            cwe=rule.get("cwe"),
                            owasp_tag=rule.get("owasp_tag"),
                        )
                        findings.append(finding)
        return findings


class ASTScanner:
    """Coordinator for Abstract Syntax Tree and semantic code scanning."""

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)
        self.languages = [l.lower() for l in self.config.get("languages", ["python", "javascript", "typescript", "go", "sh"])]
        self.rules_config = self.config.get("rules", {})
        self.ml_scanner = MultiLanguagePatternScanner()

    def scan_source(self, file_path: str, code_content: str) -> List[Finding]:
        """Scans source code using Python AST if python file, or multi-language rules."""
        if not self.enabled:
            return []

        findings: List[Finding] = []
        ext = os.path.splitext(file_path)[1].lower()

        if ext == ".py" and ("python" in self.languages or not self.languages):
            try:
                tree = ast.parse(code_content, filename=file_path)
                visitor = PythonASTVisitor(file_path, code_content.splitlines(), rules_config=self.rules_config)
                visitor.visit(tree)
                findings.extend(visitor.findings)
            except SyntaxError:
                # If code is a partial fragment or contains syntax error, fall back gracefully
                pass

        # Multi-language checks
        findings.extend(self.ml_scanner.scan_file(file_path, code_content))
        return findings

    def scan_diff_file(self, diff_file, base_dir: str = ".") -> List[Finding]:
        """Scans a diff file, filtering findings to lines that were modified or added."""
        if not self.enabled:
            return []

        findings: List[Finding] = []
        target_path = diff_file.target_path
        added_lines = set(diff_file.get_added_line_numbers())

        full_path = os.path.join(base_dir, target_path)
        content_to_scan: Optional[str] = None

        if os.path.exists(full_path) and os.path.isfile(full_path):
            try:
                with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                    content_to_scan = f.read()
            except Exception:
                pass

        if not content_to_scan:
            # Reconstruct added lines into a pseudo file for analysis
            reconstructed: List[str] = []
            for hunk in diff_file.hunks:
                for line in hunk.lines:
                    if line.is_addition or line.is_context:
                        reconstructed.append(line.content)
            content_to_scan = "\n".join(reconstructed)

        all_findings = self.scan_source(target_path, content_to_scan)

        # If we have added_lines information, restrict findings to those lines
        if added_lines:
            for f in all_findings:
                if f.line_number in added_lines:
                    findings.append(f)
        else:
            findings.extend(all_findings)

        return findings
