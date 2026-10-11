"""
GitGhost package main entrypoint module.
Allows running GitGhost directly via `python -m gitghost`.
Copyright 2026 EvoderDev. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import sys
from gitghost.cli import main

if __name__ == "__main__":
    main()
