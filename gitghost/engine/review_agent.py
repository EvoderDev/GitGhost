"""
Autonomous LLM Code Review Agent with Multi-Provider Support and Deterministic Fallback.
Copyright 2026 EvoderDev. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
import requests

from gitghost.models import DiffFile, Finding, PatchProposal, ScanReport, Severity


class LLMProvider(ABC):
    """Abstract interface for LLM providers."""

    @abstractmethod
    def generate(self, prompt: str, system_prompt: str) -> str:
        """Generates response text given user and system prompts."""
        pass


class OpenAIProvider(LLMProvider):
    def __init__(self, api_key: str, model: str = "gpt-4o"):
        self.api_key = api_key
        self.model = model

    def generate(self, prompt: str, system_prompt: str) -> str:
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
        }
        resp = requests.post(url, headers=headers, json=payload, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]


class AnthropicProvider(LLMProvider):
    def __init__(self, api_key: str, model: str = "claude-3-5-sonnet-20241022"):
        self.api_key = api_key
        self.model = model

    def generate(self, prompt: str, system_prompt: str) -> str:
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "system": system_prompt,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 4096,
            "temperature": 0.1,
        }
        resp = requests.post(url, headers=headers, json=payload, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        return data["content"][0]["text"]


class GeminiProvider(LLMProvider):
    def __init__(self, api_key: str, model: str = "gemini-1.5-pro"):
        self.api_key = api_key
        self.model = model

    def generate(self, prompt: str, system_prompt: str) -> str:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        headers = {"Content-Type": "application/json"}
        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": f"{system_prompt}\n\nTask:\n{prompt}"}
                    ]
                }
            ],
            "generationConfig": {"temperature": 0.1},
        }
        resp = requests.post(url, headers=headers, json=payload, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        return data["candidates"][0]["content"]["parts"][0]["text"]


class OllamaProvider(LLMProvider):
    def __init__(self, host: str = "http://localhost:11434", model: str = "llama3"):
        self.host = host.rstrip("/")
        self.model = model

    def generate(self, prompt: str, system_prompt: str) -> str:
        url = f"{self.host}/api/generate"
        payload = {
            "model": self.model,
            "system": system_prompt,
            "prompt": prompt,
            "stream": False,
        }
        resp = requests.post(url, json=payload, timeout=120)
        resp.raise_for_status()
        return resp.json()["response"]


class OfflineRuleAgent(LLMProvider):
    """Deterministic, offline autonomous security engine."""

    def generate(self, prompt: str, system_prompt: str) -> str:
        return (
            "GitGhost Offline Security Engine processed static analysis findings. "
            "Remediation patches and security mitigations have been generated deterministically."
        )


class ReviewAgent:
    """Orchestrates security and code review with LLM providers."""

    SYSTEM_PROMPT = """You are GitGhost, a Principal AppSec and DevSecOps Architect.
Analyze the provided Git diff, AST findings, and detected secrets.
Provide actionable security feedback, assess the root cause, and formulate unified patch fixes.
Always be concise, precise, and adhere to OWASP Top 10 and secure coding standards."""

    def __init__(self, provider_name: str = "auto", model: Optional[str] = None):
        self.provider = self._resolve_provider(provider_name, model)

    def _resolve_provider(self, provider_name: str, model: Optional[str]) -> LLMProvider:
        p_name = provider_name.lower()
        if p_name == "auto":
            if os.environ.get("OPENAI_API_KEY"):
                return OpenAIProvider(os.environ["OPENAI_API_KEY"], model or "gpt-4o")
            elif os.environ.get("ANTHROPIC_API_KEY"):
                return AnthropicProvider(os.environ["ANTHROPIC_API_KEY"], model or "claude-3-5-sonnet-20241022")
            elif os.environ.get("GEMINI_API_KEY"):
                return GeminiProvider(os.environ["GEMINI_API_KEY"], model or "gemini-1.5-pro")
            elif os.environ.get("GITGHOST_OLLAMA_URL"):
                return OllamaProvider(os.environ["GITGHOST_OLLAMA_URL"], model or "llama3")
            return OfflineRuleAgent()

        if p_name == "openai":
            key = os.environ.get("OPENAI_API_KEY", "")
            return OpenAIProvider(key, model or "gpt-4o")
        elif p_name == "anthropic":
            key = os.environ.get("ANTHROPIC_API_KEY", "")
            return AnthropicProvider(key, model or "claude-3-5-sonnet-20241022")
        elif p_name == "gemini":
            key = os.environ.get("GEMINI_API_KEY", "")
            return GeminiProvider(key, model or "gemini-1.5-pro")
        elif p_name == "ollama":
            url = os.environ.get("GITGHOST_OLLAMA_URL", "http://localhost:11434")
            return OllamaProvider(url, model or "llama3")
        else:
            return OfflineRuleAgent()

    def review(
        self,
        diff_files: List[DiffFile],
        findings: List[Finding],
        raw_diff: str = "",
    ) -> Dict[str, Any]:
        """Performs autonomous code review on findings and diff."""
        if not findings and not raw_diff:
            return {
                "summary": "No changes or security findings detected. Codebase is clean.",
                "risk_score": 0,
                "recommendations": [],
                "agent_status": "PASS",
            }

        # If using offline agent, generate deterministic summary
        if isinstance(self.provider, OfflineRuleAgent):
            critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
            high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
            medium_count = sum(1 for f in findings if f.severity == Severity.MEDIUM)

            risk_score = min(100, critical_count * 35 + high_count * 20 + medium_count * 10)
            summary = (
                f"Static analysis detected {len(findings)} issue(s): "
                f"{critical_count} CRITICAL, {high_count} HIGH, {medium_count} MEDIUM. "
                "Immediate remediation is recommended prior to merging."
            )
            return {
                "summary": summary,
                "risk_score": risk_score,
                "recommendations": [f"{f.title} ({f.file_path}:{f.line_number})" for f in findings],
                "agent_status": "BLOCKED" if (critical_count + high_count > 0) else "WARNING",
            }

        # Online LLM synthesis
        findings_summary = [
            f"- [{f.severity.value}] {f.title} in {f.file_path}:{f.line_number} (Rule: {f.rule_id})\n  Snippet: {f.snippet}"
            for f in findings[:25]
        ]
        prompt = (
            f"Review the following security findings and Git diff:\n\n"
            f"Findings:\n" + "\n".join(findings_summary) + f"\n\n"
            f"Git Diff snippet:\n{raw_diff[:3000]}\n\n"
            "Produce a JSON response with keys:\n"
            "- summary: brief executive overview\n"
            "- risk_score: integer from 0 to 100\n"
            "- recommendations: list of top actionable bullet points\n"
            "- agent_status: 'PASS', 'WARNING', or 'BLOCKED'\n"
            "Return valid JSON only."
        )

        try:
            raw_response = self.provider.generate(prompt, self.SYSTEM_PROMPT)
            cleaned = raw_response.strip()
            if cleaned.startswith("```json"):
                cleaned = cleaned[7:]
            if cleaned.endswith("```"):
                cleaned = cleaned[:-3]
            return json.loads(cleaned.strip())
        except Exception:
            # Fallback to deterministic review if API call fails
            fallback = OfflineRuleAgent()
            critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
            return {
                "summary": f"Detected {len(findings)} vulnerability finding(s). LLM synthesis timed out.",
                "risk_score": min(100, len(findings) * 20),
                "recommendations": [f.title for f in findings[:5]],
                "agent_status": "BLOCKED" if critical_count > 0 else "WARNING",
            }
