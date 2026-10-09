"""
Unit tests for GitGhost DiffParser.
Copyright 2026 EvoderDev. Licensed under the Apache License, Version 2.0.
"""

from gitghost.core.diff_parser import DiffParser


SAMPLE_DIFF = """diff --git a/app/main.py b/app/main.py
index e69de29..b2b06e8 100644
--- a/app/main.py
+++ b/app/main.py
@@ -1,5 +1,6 @@
 import os
+import subprocess
 
 def execute():
-    os.system("echo old")
+    subprocess.run("echo safe", shell=False)
     return True
"""

MULTI_FILE_DIFF = """diff --git a/file1.py b/file1.py
--- a/file1.py
+++ b/file1.py
@@ -10,3 +10,4 @@
 def a():
+    pass
diff --git a/file2.py b/file2.py
new file mode 100644
--- /dev/null
+++ b/file2.py
@@ -0,0 +1,2 @@
+secret = "ghp_1234567890abcdef1234567890abcdef1234"
+print(secret)
"""


def test_diff_parser_single_file():
    parser = DiffParser(SAMPLE_DIFF)
    files = parser.parse()

    assert len(files) == 1
    file = files[0]
    assert file.old_path == "app/main.py"
    assert file.new_path == "app/main.py"
    assert len(file.hunks) == 1

    hunk = file.hunks[0]
    assert hunk.old_start == 1
    assert hunk.new_start == 1

    added = [line for line in hunk.lines if line.is_addition]
    deleted = [line for line in hunk.lines if line.is_deletion]
    context = [line for line in hunk.lines if line.is_context]

    assert len(added) == 2
    assert added[0].content == "import subprocess"
    assert added[0].new_line_no == 2
    assert added[1].content == '    subprocess.run("echo safe", shell=False)'
    assert added[1].new_line_no == 5

    assert len(deleted) == 1
    assert deleted[0].content == '    os.system("echo old")'
    assert deleted[0].old_line_no == 4

    assert len(context) >= 2


def test_diff_parser_multi_file_and_new_file():
    parser = DiffParser(MULTI_FILE_DIFF)
    files = parser.parse()

    assert len(files) == 2
    assert files[0].new_path == "file1.py"
    assert not files[0].is_new

    assert files[1].new_path == "file2.py"
    assert files[1].is_new
    assert files[1].hunks[0].new_lines == 2
    assert len(files[1].get_added_line_numbers()) == 2
