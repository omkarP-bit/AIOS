"""Model providers.

Everything here is an untrusted text generator. A provider returns text; it
never returns an action, a decision, or an authorization. Parsing and policy
happen after this boundary.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from aios.config import Settings


class ProviderError(RuntimeError):
    """Raised when a model cannot be reached or returns an unusable answer."""


@dataclass(frozen=True)
class ChatMessage:
    role: str
    content: str


class ModelProvider(Protocol):
    name: str
    model: str
    #: True when prompts leave the machine. Surfaced to callers and audit.
    external: bool

    def complete(self, system: str, user: str) -> str: ...


class GroqProvider:
    name = "groq"
    external = True

    def __init__(
        self,
        api_key: str,
        model: str,
        base_url: str = "https://api.groq.com/openai/v1",
        timeout_s: float = 30.0,
        max_tokens: int = 1024,
        temperature: float = 0.0,
    ) -> None:
        if not api_key:
            raise ProviderError(
                "Groq requires AIOS_GROQ_API_KEY and AIOS_ALLOW_EXTERNAL_MODEL=true"
            )
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        self.max_tokens = max_tokens
        self.temperature = temperature

    def complete(self, system: str, user: str) -> str:
        try:
            response = httpx.post(
                f"{self.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "temperature": self.temperature,
                    "max_tokens": self.max_tokens,
                    "response_format": {"type": "json_object"},
                },
                timeout=self.timeout_s,
            )
            response.raise_for_status()
            payload = response.json()
            content = payload["choices"][0]["message"]["content"]
        except (httpx.HTTPError, KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
            raise ProviderError(f"groq request failed: {type(exc).__name__}") from exc
        if not isinstance(content, str) or not content.strip():
            raise ProviderError("groq returned an empty completion")
        return content


class OllamaProvider:
    name = "ollama"
    external = False

    def __init__(
        self,
        model: str,
        url: str = "http://127.0.0.1:11434",
        timeout_s: float = 60.0,
        temperature: float = 0.0,
    ) -> None:
        self.model = model
        self.url = url.rstrip("/")
        self.timeout_s = timeout_s
        self.temperature = temperature

    def complete(self, system: str, user: str) -> str:
        try:
            response = httpx.post(
                f"{self.url}/api/chat",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "stream": False,
                    "format": "json",
                    "options": {"temperature": self.temperature},
                },
                timeout=self.timeout_s,
            )
            response.raise_for_status()
            payload = response.json()
            content = payload["message"]["content"]
        except (httpx.HTTPError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise ProviderError(f"ollama request failed: {type(exc).__name__}") from exc
        if not isinstance(content, str) or not content.strip():
            raise ProviderError("ollama returned an empty completion")
        return content


def build_provider(settings: Settings) -> ModelProvider:
    """Select the configured provider, refusing external use unless opted in."""
    choice = settings.model_provider.strip().lower()
    if choice == "groq":
        if not settings.allow_external_model:
            raise ProviderError(
                "external model use is disabled; set AIOS_ALLOW_EXTERNAL_MODEL=true"
            )
        return GroqProvider(
            api_key=settings.groq_api_key,
            model=settings.groq_model,
            base_url=settings.groq_base_url,
            timeout_s=settings.groq_timeout_s,
            max_tokens=settings.groq_max_tokens,
            temperature=settings.groq_temperature,
        )
    if choice == "ollama":
        return OllamaProvider(
            model=settings.ollama_model,
            url=settings.ollama_url,
            timeout_s=settings.ollama_timeout_s,
        )
    raise ProviderError(f"unknown model provider {settings.model_provider!r}")


def provider_status(settings: Settings) -> dict[str, Any]:
    """Configuration summary that never includes the API key."""
    return {
        "provider": settings.model_provider,
        "external": settings.model_provider == "groq",
        "external_allowed": settings.allow_external_model,
        "configured": settings.groq_enabled
        if settings.model_provider == "groq"
        else True,
        "model": settings.groq_model
        if settings.model_provider == "groq"
        else settings.ollama_model,
    }


__all__ = [
    "ChatMessage",
    "GroqProvider",
    "ModelProvider",
    "OllamaProvider",
    "ProviderError",
    "build_provider",
    "provider_status",
]
