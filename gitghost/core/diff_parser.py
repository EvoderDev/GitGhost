"""
Unified Git Diff Parser and Git integration.
Copyright 2026 EvoderDev. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import os
import re
import subprocess
from typing import List, Optional

from gitghost.models import DiffFile, DiffHunk, DiffLine


class DiffParser:
    """Parses standard unified diff output into structured models."""

    HUNK_HEADER_REGEX = re.compile(
        r"^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@(.*)$"
    )

    def __init__(self, diff_text: str):
        self.raw_diff = diff_text

    def parse(self) -> List[DiffFile]:
        """Parses the raw diff text into a list of DiffFile objects."""
        files: List[DiffFile] = []
        current_file: Optional[DiffFile] = None
        current_hunk: Optional[DiffHunk] = None

        old_line_counter = 0
        new_line_counter = 0

        lines = self.raw_diff.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]

            # Header: diff --git a/... b/...
            if line.startswith("diff --git "):
                if current_file:
                    if current_hunk:
                        current_file.hunks.append(current_hunk)
                        current_hunk = None
                    files.append(current_file)

                current_file = DiffFile()
                parts = line.split(" ")
                if len(parts) >= 4:
                    raw_a = parts[2]
                    raw_b = parts[3]
                    current_file.old_path = raw_a[2:] if raw_a.startswith("a/") else raw_a
                    current_file.new_path = raw_b[2:] if raw_b.startswith("b/") else raw_b
                i += 1
                continue

            if not current_file:
                i += 1
                continue

            # Check file metadata
            if line.startswith("new file mode"):
                current_file.is_new = True
                i += 1
                continue
            elif line.startswith("deleted file mode"):
                current_file.is_deleted = True
                i += 1
                continue
            elif line.startswith("Binary files"):
                current_file.is_binary = True
                i += 1
                continue
            elif line.startswith("rename from "):
                current_file.old_path = line[len("rename from "):].strip()
                i += 1
                continue
            elif line.startswith("rename to "):
                current_file.new_path = line[len("rename to "):].strip()
                i += 1
                continue
            elif line.startswith("--- "):
                raw_path = line[4:].strip()
                if raw_path.startswith("a/"):
                    current_file.old_path = raw_path[2:]
                elif raw_path == "/dev/null":
                    current_file.is_new = True
                else:
                    current_file.old_path = raw_path
                i += 1
                continue
            elif line.startswith("+++ "):
                raw_path = line[4:].strip()
                if raw_path.startswith("b/"):
                    current_file.new_path = raw_path[2:]
                elif raw_path == "/dev/null":
                    current_file.is_deleted = True
                else:
                    current_file.new_path = raw_path
                i += 1
                continue

            # Hunk header: @@ -a,b +c,d @@
            hunk_match = self.HUNK_HEADER_REGEX.match(line)
            if hunk_match:
                if current_hunk:
                    current_file.hunks.append(current_hunk)

                old_start = int(hunk_match.group(1))
                old_lines = int(hunk_match.group(2)) if hunk_match.group(2) else 1
                new_start = int(hunk_match.group(3))
                new_lines = int(hunk_match.group(4)) if hunk_match.group(4) else 1
                header_context = hunk_match.group(5).strip()

                current_hunk = DiffHunk(
                    old_start=old_start,
                    old_lines=old_lines,
                    new_start=new_start,
                    new_lines=new_lines,
                    header=header_context,
                    lines=[],
                )
                old_line_counter = old_start
                new_line_counter = new_start
                i += 1
                continue

            # Diff content lines
            if current_hunk is not None:
                if line.startswith("+"):
                    diff_line = DiffLine(
                        origin="+",
                        content=line[1:],
                        old_line_no=None,
                        new_line_no=new_line_counter,
                    )
                    new_line_counter += 1
                    current_hunk.lines.append(diff_line)
                elif line.startswith("-"):
                    diff_line = DiffLine(
                        origin="-",
                        content=line[1:],
                        old_line_no=old_line_counter,
                        new_line_no=None,
                    )
                    old_line_counter += 1
                    current_hunk.lines.append(diff_line)
                elif line.startswith(" "):
                    diff_line = DiffLine(
                        origin=" ",
                        content=line[1:],
                        old_line_no=old_line_counter,
                        new_line_no=new_line_counter,
                    )
                    old_line_counter += 1
                    new_line_counter += 1
                    current_hunk.lines.append(diff_line)
                elif line.startswith("\\ No newline at end of file"):
                    # Ignore git warning marker
                    pass

            i += 1

        if current_file:
            if current_hunk:
                current_file.hunks.append(current_hunk)
            files.append(current_file)

        return files


def get_git_diff(
    repo_path: str = ".",
    staged: bool = False,
    commit: Optional[str] = None,
    base_ref: Optional[str] = None,
    head_ref: Optional[str] = None,
    file_path: Optional[str] = None,
) -> str:
    """Executes git diff command in repo_path and returns unified diff string."""
    cmd = ["git", "diff", "--unified=3"]

    if staged:
        cmd.append("--staged")
    elif commit:
        cmd.extend([f"{commit}~1", commit])
    elif base_ref and head_ref:
        cmd.append(f"{base_ref}...{head_ref}")
    elif base_ref:
        cmd.append(base_ref)

    if file_path:
        cmd.extend(["--", file_path])

    try:
        result = subprocess.run(
            cmd,
            cwd=repo_path,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if result.returncode != 0:
            return ""
        return result.stdout
    except Exception:
        return ""
