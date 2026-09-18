"""Provider-agnostic LLM client.

The narrative layer is a *wrapper around findings*, not a source of them. The
prompt is constructed from the engine's output only, the model is told
explicitly that it may not introduce findings or alter the score, and every
response is validated against the assessment before it is accepted
(`validation.py`). Anything that fails validation is discarded in favour of the
deterministic narrative.
"""
from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from typing import Any

DEFAULT_TIMEOUT = 45.0
MAX_TOKENS = 2000


class LLMError(Exception):
    """The provider could not be reached, or returned something unusable."""


class LLMProvider(ABC):
    name = "abstract"
    model = "unknown"

    @abstractmethod
    def complete(self, system: str, user: str) -> str:
        """Return the model's raw text response."""

    @property
    def configured(self) -> bool:
        return True


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(self, api_key: str | None = None, model: str | None = None,
                 timeout: float = DEFAULT_TIMEOUT):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.model = model or os.environ.get("SMS_LLM_MODEL", "claude-sonnet-4-5")
        self.timeout = timeout

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def complete(self, system: str, user: str) -> str:
        if not self.configured:
            raise LLMError("ANTHROPIC_API_KEY is not set")

        payload = {
            "model": self.model,
            "max_tokens": MAX_TOKENS,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        data = self._post(
            "https://api.anthropic.com/v1/messages",
            payload,
            {
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
        )
        try:
            return "".join(
                block.get("text", "") for block in data["content"]
                if block.get("type") == "text"
            )
        except (KeyError, TypeError) as exc:
            raise LLMError(f"unexpected response shape: {exc}")

    def _post(self, url: str, payload: dict[str, Any],
              headers: dict[str, str]) -> dict[str, Any]:
        import urllib.error
        import urllib.request

        req = urllib.request.Request(
            url, data=json.dumps(payload).encode(), headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")[:400]
            raise LLMError(f"HTTP {exc.code} from {self.name}: {body}")
        except Exception as exc:
            raise LLMError(f"{type(exc).__name__}: {exc}")


class OpenAICompatibleProvider(AnthropicProvider):
    """Works with OpenAI, Groq, Together, OpenRouter and anything else that
    speaks the /chat/completions shape. Useful if API credit is a constraint on
    demo day."""

    name = "openai-compatible"

    def __init__(self, api_key: str | None = None, model: str | None = None,
                 base_url: str | None = None, timeout: float = DEFAULT_TIMEOUT):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.model = model or os.environ.get("SMS_LLM_MODEL", "gpt-4o-mini")
        self.base_url = (base_url or os.environ.get(
            "SMS_LLM_BASE_URL", "https://api.openai.com/v1")).rstrip("/")
        self.timeout = timeout

    def complete(self, system: str, user: str) -> str:
        if not self.configured:
            raise LLMError("OPENAI_API_KEY is not set")

        data = self._post(
            f"{self.base_url}/chat/completions",
            {
                "model": self.model,
                "max_tokens": MAX_TOKENS,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
            {
                "authorization": f"Bearer {self.api_key}",
                "content-type": "application/json",
            },
        )
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"unexpected response shape: {exc}")


def build_provider(name: str | None = None) -> LLMProvider | None:
    """Pick a provider from configuration. Returns None when none is configured,
    which is a normal state — the deterministic narrative covers it."""
    name = (name or os.environ.get("SMS_LLM_PROVIDER", "auto")).lower()

    if name in ("none", "off", "disabled"):
        return None
    if name == "anthropic":
        return AnthropicProvider()
    if name in ("openai", "openai-compatible", "compatible"):
        return OpenAICompatibleProvider()

    for candidate in (AnthropicProvider(), OpenAICompatibleProvider()):
        if candidate.configured:
            return candidate
    return None
