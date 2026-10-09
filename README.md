<div align="center">

```
   ____ _ _    ____ _               _   
  / ___(_) |_ / ___| |__   ___  ___| |_ 
 | |  _| | __| |  _| '_ \ / _ \/ __| __|
 | |_| | | |_| |_| | | | | (_) \__ \ |_ 
  \____|_|\__|\____|_| |_|\___/|___/\__|
```

### **Autonomous Git Diff, AST & Secret Security Scanner with LLM Patch Engine**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/Python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-3776AB.svg?logo=python&logoColor=white)](pyproject.toml)
[![CI Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg?logo=github-actions&logoColor=white)](.github/workflows/test.yml)
[![OWASP Top 10](https://img.shields.io/badge/Security-OWASP%20Top%2010-orange.svg)](https://owasp.org/www-project-top-ten/)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0%20Compliant-purple.svg)](https://sarifweb.azurewebsites.net/)
[![Code Style](https://img.shields.io/badge/Code%20Style-Black-000000.svg)](https://github.com/psf/black)

[Features](#-key-features) • [Architecture](#-architecture) • [Installation](#-installation) • [CLI Commands](#-cli-reference) • [GitHub Action](#-github-actions-ci-integration) • [Rules Catalog](#-vulnerability-rules--owasp-catalog) • [License](#-license)

---

</div>

## 📌 Overview

**GitGhost** is an autonomous DevSecOps security scanner and remediation engine designed for high-velocity software engineering teams. Operating directly on **Git Diffs** and full codebases, GitGhost fuses **Shannon entropy analysis**, **deep Abstract Syntax Tree (AST) inspection**, and an **autonomous LLM reasoning engine** to detect critical security vulnerabilities, secret leaks, and performance defects before code merges.

Beyond detection, GitGhost acts as an autonomous engineer: it synthesizes root causes, formats findings into GitHub-compliant **SARIF v2.1.0** alerts, and generates mathematically sound **unified diff patches (`.patch`)** that can be reviewed interactively in terminal or applied automatically.

---

## ⚡ Key Features

* **🎯 Micro-Hunk Git Diff Parsing:** Computes precise 1-based line mappings on additions and deletions, scanning only changed code lines without bloated full-repository overhead.
* **🔑 Zero-False-Negative Secret Hunter:** Combines strict regex tokens with Shannon entropy metrics ($H(X) \ge 4.3$) to detect GitHub PATs, AWS Keys, OpenAI/Anthropic/Gemini tokens, Slack webhooks, database connection strings, and private keys while automatically suppressing test placeholders.
* **🛡️ Deep AST & Semantic Vulnerability Scanner:**
  * **OWASP A03:2021 (Injection):** SQL Injection in dynamic queries, Command Injection (`os.system`, `subprocess(shell=True)`), Dynamic execution (`eval`, `exec`).
  * **OWASP A08:2021 (Software/Data Integrity):** Unsafe YAML deserialization (`yaml.load`), arbitrary bytecode execution (`pickle.loads`).
  * **OWASP A02:2021 (Cryptographic Failures):** Deprecated hash functions (`MD5`, `SHA-1`), insecure pseudo-randomness in tokens.
  * **⚡ High-Impact Performance Anti-Patterns:** $O(N^2)$ quadratic string concatenations inside loops, event-loop freezing (`time.sleep` in async coroutines).
* **🤖 Autonomous LLM Review Agent:** Multi-provider reasoning supporting **OpenAI (GPT-4o)**, **Anthropic (Claude 3.5)**, **Google Gemini**, **Ollama (local)**, and an intelligent **Deterministic Offline Fallback Engine** that operates seamlessly without network or API keys.
* **🛠️ Automated Unified Patch Engine:** Generates standards-compliant unified diff patches that can be interactively previewed, saved (`--output-patch`), or immediately applied (`--apply`).
* **🎨 Cyberpunk Rich Terminal UI:** Interactive terminal experience powered by `rich`, featuring severity badges, syntax-highlighted diffs, executive summary cards, and dual entry points (`gitghost` and `gh-ghost`).
* **🚀 Native GitHub Actions & PR Bot:** Auto-detects CI environments, submits inline review comments on pull request diffs, writes rich `$GITHUB_STEP_SUMMARY` reports, and exports SARIF for GitHub Code Scanning.

---

## 🏛 Architecture

```
                          ┌───────────────────────────┐
                          │   Git Diff / Source Code  │
                          └─────────────┬─────────────┘
                                        │
                         ┌──────────────┴──────────────┐
                         ▼                             ▼
              ┌────────────────────┐        ┌────────────────────┐
              │    Diff Parser     │        │   Secret Detector  │
              │  (Hunk & Line Map) │        │ (Entropy & Regex)  │
              └──────────┬─────────┘        └──────────┬─────────┘
                         │                             │
                         ▼                             ▼
              ┌────────────────────┐        ┌────────────────────┐
              │     AST Scanner    │        │ Hardcoded Secrets  │
              │   (OWASP & Perf)   │        │     (CWE-798)      │
              └──────────┬─────────┘        └──────────┬─────────┘
                         │                             │
                         └──────────────┬──────────────┘
                                        │
                                        ▼
                         ┌─────────────────────────────┐
                         │   Autonomous Review Agent   │
                         │ (OpenAI / Claude / Offline) │
                         └──────────────┬──────────────┘
                                        │
                    ┌───────────────────┴───────────────────┐
                    ▼                                       ▼
         ┌─────────────────────┐                 ┌─────────────────────┐
         │ Unified Patch Engine│                 │ Integrators & UI    │
         │ (git apply / fixes) │                 │ (Rich, SARIF, PRs)  │
         └─────────────────────┘                 └─────────────────────┘
```

---

## 📦 Installation

### From Source (Recommended for Development)

```bash
git clone https://github.com/EvoderDev/GitGhost.git
cd GitGhost

# Install in editable mode with development dependencies
pip install -e .[dev]
```

### Verify Installation

```bash
gitghost --help
# Or use the alias
gh-ghost --help
```

---

## 💻 CLI Reference

### 1. `scan`: Analyze Git Diffs or Files

```bash
# Scan working tree diff against HEAD
gitghost scan

# Scan staged changes (pre-commit check)
gitghost scan --staged

# Scan specific commit
gitghost scan --commit abc1234

# Scan a single file or directory directly
gitghost scan --file src/api/routes.py --details

# Export GitHub-compliant SARIF report
gitghost scan --format sarif --output results.sarif

# Export JSON report
gitghost scan --format json --output report.json

# Fail CI pipeline only on critical issues
gitghost scan --fail-on critical
```

### 2. `fix`: Autonomously Generate & Apply Patches

```bash
# Scan and interactively prompt before applying fixes
gitghost fix

# Scan staged changes and save unified patch to a file
gitghost fix --staged --output-patch security_fix.patch

# Automatically apply all recommended patches without prompting
gitghost fix --file app.py --apply
```

### 3. `review`: Deep Autonomous LLM Review

```bash
# Automatically selects OpenAI, Anthropic, Gemini, or Offline fallback
gitghost review

# Use local LLM via Ollama
export GITGHOST_OLLAMA_URL="http://localhost:11434"
gitghost review --provider ollama --model llama3

# Force offline deterministic engine
gitghost review --provider offline
```

### 4. `init`: Initialize Project & Pre-Commit Hook

```bash
# Creates .gitghost.yaml and installs pre-commit hook into .git/hooks/pre-commit
gitghost init
```

---

## ⚙️ Configuration (`.gitghost.yaml`)

Customize rules, thresholds, and exclusions via `.gitghost.yaml` at your repository root:

```yaml
version: "1.0"

# Minimum severity to display: info, low, medium, high, critical
min_severity: "low"

# Minimum severity that exits with code 1
fail_on: "high"

# Patterns excluded from scanning
exclude_patterns:
  - "tests/**"
  - "*.min.js"
  - "node_modules/**"
  - "dist/**"

# Secret detection settings
secrets:
  enabled: true
  min_entropy: 4.3
  ignored_patterns:
    - "^EXAMPLE_.*"
    - ".*dummy.*"

# Static AST analysis rules
ast:
  enabled: true
  rules:
    sqli: true
    rce: true
    path_traversal: true
    insecure_deserialization: true
    weak_cryptography: true
    quadratic_string_concat: true

# Autonomous LLM Engine settings
engine:
  provider: "auto" # auto, openai, anthropic, gemini, ollama, offline
  temperature: 0.1
  generate_patches: true
```

---

## 🤖 GitHub Actions CI Integration

Add GitGhost to `.github/workflows/security.yml` to automatically review every Pull Request and upload SARIF alerts to GitHub Code Scanning:

```yaml
name: "GitGhost Security Gate"

on:
  push:
    branches: [ "main", "develop" ]
  pull_request:
    branches: [ "main", "develop" ]

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install GitGhost
        run: pip install gitghost

      - name: Run GitGhost Gate & Export SARIF
        run: gitghost scan --fail-on high --format sarif --output results.sarif

      - name: Upload to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif

      - name: Run GitGhost PR Bot Review
        if: github.event_name == 'pull_request'
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: gitghost ci --fail-on high
```

---

## 📋 Vulnerability Rules & OWASP Catalog

| Rule ID | Severity | Category | Target / Description | CWE | OWASP Top 10 |
| :--- | :---: | :--- | :--- | :---: | :---: |
| `GHOST-SEC-001` | **CRITICAL** | `SECRET_LEAK` | GitHub PAT (`ghp_`, `github_pat_`) | CWE-798 | A02:2021 |
| `GHOST-SEC-002` | **HIGH** | `SECRET_LEAK` | AWS Access Key ID (`AKIA...`) | CWE-798 | A02:2021 |
| `GHOST-SEC-003` | **CRITICAL** | `SECRET_LEAK` | AWS Secret Access Key | CWE-798 | A02:2021 |
| `GHOST-SEC-004` | **CRITICAL** | `SECRET_LEAK` | OpenAI API Key (`sk-...`, `sk-proj-...`) | CWE-798 | A02:2021 |
| `GHOST-SEC-005` | **CRITICAL** | `SECRET_LEAK` | Anthropic Claude Key (`sk-ant-...`) | CWE-798 | A02:2021 |
| `GHOST-SEC-006` | **CRITICAL** | `SECRET_LEAK` | Google Cloud / Gemini API Key (`AIza...`) | CWE-798 | A02:2021 |
| `GHOST-SEC-008` | **CRITICAL** | `SECRET_LEAK` | Private RSA/EC/OpenSSH Key | CWE-312 | A02:2021 |
| `GHOST-SEC-009` | **CRITICAL** | `SECRET_LEAK` | Database URI with plaintext password | CWE-312 | A02:2021 |
| `GHOST-SQL-001` | **CRITICAL** | `OWASP_SQLI` | SQL Injection via string formatting in execute() | CWE-89 | A03:2021 |
| `GHOST-RCE-001` | **CRITICAL** | `OWASP_RCE` | Dynamic code execution via `eval()` or `exec()` | CWE-94 | A03:2021 |
| `GHOST-RCE-002` | **CRITICAL** | `OWASP_RCE` | Command Injection via `os.system()` | CWE-78 | A03:2021 |
| `GHOST-RCE-003` | **CRITICAL** | `OWASP_RCE` | Shell injection via `subprocess(shell=True)` | CWE-78 | A03:2021 |
| `GHOST-DESER-001` | **HIGH** | `OWASP_DESER` | Insecure Deserialization via `pickle.loads()` | CWE-502 | A08:2021 |
| `GHOST-DESER-002` | **HIGH** | `OWASP_DESER` | Unsafe YAML loading (`yaml.load()` without SafeLoader) | CWE-502 | A08:2021 |
| `GHOST-CRYPTO-001` | **MEDIUM** | `OWASP_CRYPTO` | Broken hashing algorithm (`MD5`, `SHA-1`) | CWE-327 | A02:2021 |
| `GHOST-PERF-001` | **MEDIUM** | `PERFORMANCE` | Quadratic string concatenation in loop ($O(N^2)$) | CWE-400 | Quality |
| `GHOST-PERF-002` | **HIGH** | `PERFORMANCE` | Blocking `time.sleep()` in async coroutine | CWE-400 | Quality |
| `GHOST-JS-XSS-001` | **HIGH** | `OWASP_XSS` | Untrusted assignment to `innerHTML` | CWE-79 | A03:2021 |

---

## 🧪 Testing

GitGhost includes a comprehensive test suite covering diff parsing, entropy analysis, AST vulnerability detection, autonomous patch generation, and CLI runner execution.

```bash
# Run tests with pytest
pytest tests/ -v

# Run with test coverage
pytest tests/ --cov=gitghost --cov-report=term-missing
```

---

## 📄 License

Distributed under the **Apache License 2.0**. See [`LICENSE`](LICENSE) for complete terms.

```text
Copyright 2026 EvoderDev

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
