"""
GitGhost - Autonomous Git Diff, AST & Secret Security Scanner with LLM Patch Engine.
Copyright 2026 EvoderDev. Licensed under the Apache License, Version 2.0.
"""

__version__ = "1.0.0"
__author__ = "EvoderDev"
__license__ = "Apache-2.0"

from gitghost.models import (
    Category,
    DiffFile,
    DiffHunk,
    DiffLine,
    Finding,
    PatchProposal,
    ScanReport,
    Severity,
)

__all__ = [
    "Category",
    "DiffFile",
    "DiffHunk",
    "DiffLine",
    "Finding",
    "PatchProposal",
    "ScanReport",
    "Severity",
    "__version__",
]
