"""
Data models and type definitions for GitGhost.
Copyright 2026 EvoderDev. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import json
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Vulnerability and finding severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        levels = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return levels.get(self, 0)

    def __ge__(self, other: Severity) -> bool:
        if isinstance(other, Severity):
            return self.rank >= other.rank
        return NotImplemented

    def __gt__(self, other: Severity) -> bool:
        if isinstance(other, Severity):
            return self.rank > other.rank
        return NotImplemented

    def __le__(self, other: Severity) -> bool:
        if isinstance(other, Severity):
            return self.rank <= other.rank
        return NotImplemented

    def __lt__(self, other: Severity) -> bool:
        if isinstance(other, Severity):
            return self.rank < other.rank
        return NotImplemented


class Category(str, Enum):
    """Categorization of findings."""
    SECRET_LEAK = "SECRET_LEAK"
    OWASP_SQLI = "OWASP_SQLI"
    OWASP_RCE = "OWASP_RCE"
    OWASP_PATH_TRAVERSAL = "OWASP_PATH_TRAVERSAL"
    OWASP_DESERIALIZATION = "OWASP_DESERIALIZATION"
    OWASP_CRYPTO = "OWASP_CRYPTO"
    OWASP_XSS = "OWASP_XSS"
    OWASP_SSRF = "OWASP_SSRF"
    PERFORMANCE = "PERFORMANCE"
    CODE_SMELL = "CODE_SMELL"


class Finding(BaseModel):
    """Represents a security or performance vulnerability finding."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    file_path: str
    line_number: int
    column: Optional[int] = None
    end_line: Optional[int] = None
    severity: Severity
    category: Category
    rule_id: str
    title: str
    description: str
    snippet: str
    remediation: str
    suggested_fix: Optional[str] = None
    cwe: Optional[str] = None
    owasp_tag: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class DiffLine(BaseModel):
    """Individual line inside a diff hunk."""
    origin: str  # '+', '-', ' '
    content: str
    old_line_no: Optional[int] = None
    new_line_no: Optional[int] = None

    @property
    def is_addition(self) -> bool:
        return self.origin == "+"

    @property
    def is_deletion(self) -> bool:
        return self.origin == "-"

    @property
    def is_context(self) -> bool:
        return self.origin == " "


class DiffHunk(BaseModel):
    """A hunk within a unified diff file."""
    old_start: int
    old_lines: int
    new_start: int
    new_lines: int
    header: str
    lines: List[DiffLine] = Field(default_factory=list)


class DiffFile(BaseModel):
    """Changed file representation within a git diff."""
    old_path: Optional[str] = None
    new_path: Optional[str] = None
    is_new: bool = False
    is_deleted: bool = False
    is_binary: bool = False
    hunks: List[DiffHunk] = Field(default_factory=list)

    @property
    def target_path(self) -> str:
        return self.new_path or self.old_path or "unknown"

    def get_added_line_numbers(self) -> List[int]:
        added: List[int] = []
        for hunk in self.hunks:
            for line in hunk.lines:
                if line.is_addition and line.new_line_no is not None:
                    added.append(line.new_line_no)
        return added


class PatchProposal(BaseModel):
    """An autonomous remediation patch proposal for a file."""
    file_path: str
    original_content: Optional[str] = None
    patched_content: Optional[str] = None
    unified_diff: str
    findings_addressed: List[str] = Field(default_factory=list)
    rationale: str


class ScanReport(BaseModel):
    """Comprehensive scan results report."""
    findings: List[Finding] = Field(default_factory=list)
    scanned_files_count: int = 0
    scanned_lines_count: int = 0
    patches: List[PatchProposal] = Field(default_factory=list)
    passed: bool = True
    risk_score: int = 0  # 0 to 100

    def calculate_metrics(self, fail_threshold: Severity = Severity.HIGH) -> None:
        """Calculate pass status and risk score based on findings."""
        if not self.findings:
            self.passed = True
            self.risk_score = 0
            return

        has_blocking = any(f.severity >= fail_threshold for f in self.findings)
        self.passed = not has_blocking

        score = 0
        weights = {
            Severity.CRITICAL: 35,
            Severity.HIGH: 20,
            Severity.MEDIUM: 10,
            Severity.LOW: 3,
            Severity.INFO: 1,
        }
        for f in self.findings:
            score += weights.get(f.severity, 0)
        self.risk_score = min(100, score)

    def to_sarif(self) -> Dict[str, Any]:
        """Convert findings into GitHub-compliant SARIF v2.1.0 format."""
        rules_map: Dict[str, Dict[str, Any]] = {}
        results: List[Dict[str, Any]] = []

        for finding in self.findings:
            if finding.rule_id not in rules_map:
                sarif_level = "error" if finding.severity in (Severity.CRITICAL, Severity.HIGH) else (
                    "warning" if finding.severity == Severity.MEDIUM else "note"
                )
                rules_map[finding.rule_id] = {
                    "id": finding.rule_id,
                    "name": finding.category.value,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "defaultConfiguration": {"level": sarif_level},
                    "properties": {
                        "tags": [finding.category.value, finding.severity.value] + (
                            [finding.owasp_tag] if finding.owasp_tag else []
                        ),
                        "precision": "high",
                    },
                }

            result_entry = {
                "ruleId": finding.rule_id,
                "level": "error" if finding.severity in (Severity.CRITICAL, Severity.HIGH) else (
                    "warning" if finding.severity == Severity.MEDIUM else "note"
                ),
                "message": {"text": f"{finding.title}: {finding.description}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.file_path.replace("\\", "/"),
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": finding.line_number,
                                "startColumn": finding.column or 1,
                                "endLine": finding.end_line or finding.line_number,
                            },
                        }
                    }
                ],
            }
            results.append(result_entry)

        sarif_payload = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "GitGhost",
                            "semanticVersion": "1.0.0",
                            "informationUri": "https://github.com/EvoderDev/GitGhost",
                            "rules": list(rules_map.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }
        return sarif_payload

    def to_json(self, indent: int = 2) -> str:
        return self.model_dump_json(indent=indent)
