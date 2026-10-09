"""
Unit tests for GitGhost ASTScanner.
Copyright 2026 EvoderDev. Licensed under the Apache License, Version 2.0.
"""

from gitghost.core.ast_scanner import ASTScanner
from gitghost.models import Category, Severity


def test_ast_sqli_detection():
    scanner = ASTScanner()
    code = """
import sqlite3

def get_user(cursor, user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    cursor.execute("SELECT * FROM users WHERE name = " + user_id)
"""
    findings = scanner.scan_source("db.py", code)
    sqli_findings = [f for f in findings if f.category == Category.OWASP_SQLI]

    assert len(sqli_findings) >= 1
    assert sqli_findings[0].severity == Severity.CRITICAL
    assert sqli_findings[0].rule_id == "GHOST-SQL-001"


def test_ast_command_injection():
    scanner = ASTScanner()
    code = """
import os
import subprocess

def run_cmd(user_arg):
    os.system("ping " + user_arg)
    subprocess.run("ls -la " + user_arg, shell=True)
"""
    findings = scanner.scan_source("runner.py", code)
    rce_findings = [f for f in findings if f.category == Category.OWASP_RCE]

    assert len(rce_findings) == 2
    rule_ids = {f.rule_id for f in rce_findings}
    assert "GHOST-RCE-002" in rule_ids
    assert "GHOST-RCE-003" in rule_ids


def test_ast_insecure_deserialization():
    scanner = ASTScanner()
    code = """
import pickle
import yaml

def load_payload(raw_bytes, raw_yaml):
    data = pickle.loads(raw_bytes)
    doc = yaml.load(raw_yaml)
    return data, doc
"""
    findings = scanner.scan_source("parser.py", code)
    deser_findings = [f for f in findings if f.category == Category.OWASP_DESERIALIZATION]

    assert len(deser_findings) == 2
    rule_ids = {f.rule_id for f in deser_findings}
    assert "GHOST-DESER-001" in rule_ids
    assert "GHOST-DESER-002" in rule_ids


def test_ast_weak_crypto():
    scanner = ASTScanner()
    code = """
import hashlib

def hash_pw(pw):
    return hashlib.md5(pw.encode()).hexdigest()
"""
    findings = scanner.scan_source("auth.py", code)
    crypto_findings = [f for f in findings if f.category == Category.OWASP_CRYPTO]

    assert len(crypto_findings) == 1
    assert crypto_findings[0].rule_id == "GHOST-CRYPTO-001"


def test_ast_performance_quadratic_loop():
    scanner = ASTScanner()
    code = """
def build_report(items):
    out = ""
    for item in items:
        out += str(item)
    return out
"""
    findings = scanner.scan_source("perf.py", code)
    perf_findings = [f for f in findings if f.category == Category.PERFORMANCE]

    assert len(perf_findings) == 1
    assert perf_findings[0].rule_id == "GHOST-PERF-001"


def test_ast_multilanguage_js_xss():
    scanner = ASTScanner()
    js_code = """
function render(userInput) {
    document.getElementById("output").innerHTML = userInput;
}
"""
    findings = scanner.scan_source("component.js", js_code)
    xss = [f for f in findings if f.category == Category.OWASP_XSS]
    assert len(xss) == 1
    assert xss[0].rule_id == "GHOST-JS-XSS-001"
