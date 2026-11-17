"""Model providers.

Everything here is an untrusted text generator. A provider returns text; it
never returns an action, a decision, or an authorization. Parsing and policy
happen after this boundary.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from aios.ai.env import load_dotenv


class ProviderError(RuntimeError):
    """Raised when a model cannot be reached or returns an unusable answer."""


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, fallback: float) -> float:
    try:
        return float(os.environ.get(name, "") or fallback)
    except ValueError:
        return fallback


def _env_int(name: str, fallback: int) -> int:
    try:
        return int(os.environ.get(name, "") or fallback)
    except ValueError:
        return fallback


@dataclass(frozen=True)
class ProviderSettings:
    """Model configuration read from the same AIOS_* variables as the core."""

    model_provider: str = "ollama"
    allow_external_model: bool = False
    groq_api_key: str = ""
    groq_base_url: str = "https://api.groq.com/openai/v1"
    groq_model: str = "qwen/qwen3.8-27b"
    groq_timeout_s: float = 30.0
    groq_max_tokens: int = 900
    groq_temperature: float = 0.0
    ollama_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "qwen2.5:3b-instruct-q4_K_M"
    ollama_timeout_s: float = 60.0

    @classmethod
    def from_env(cls) -> ProviderSettings:
        load_dotenv()
        return cls(
            model_provider=os.environ.get("AIOS_MODEL_PROVIDER", "ollama"),
            allow_external_model=_env_flag("AIOS_ALLOW_EXTERNAL_MODEL"),
            groq_api_key=os.environ.get("AIOS_GROQ_API_KEY", ""),
            groq_base_url=os.environ.get("AIOS_GROQ_BASE_URL", "https://api.groq.com/openai/v1"),
            groq_model=os.environ.get("AIOS_GROQ_MODEL", "qwen/qwen3.8-27b"),
            groq_timeout_s=_env_float("AIOS_GROQ_TIMEOUT_S", 30.0),
            groq_max_tokens=_env_int("AIOS_GROQ_MAX_TOKENS", 900),
            groq_temperature=_env_float("AIOS_GROQ_TEMPERATURE", 0.0),
            ollama_url=os.environ.get("AIOS_OLLAMA_URL", "http://127.0.0.1:11434"),
            ollama_model=os.environ.get("AIOS_OLLAMA_MODEL", "qwen2.5:3b-instruct-q4_K_M"),
            ollama_timeout_s=_env_float("AIOS_OLLAMA_TIMEOUT_S", 60.0),
        )

    @property
    def groq_enabled(self) -> bool:
        return self.allow_external_model and bool(self.groq_api_key)


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
        max_tokens: int = 900,
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
        except httpx.HTTPStatusError as exc:
            raise ProviderError(
                f"groq rejected the request ({exc.response.status_code}): "
                f"{_error_detail(exc.response)}"
            ) from exc
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
        except httpx.HTTPStatusError as exc:
            raise ProviderError(
                f"ollama rejected the request ({exc.response.status_code}): "
                f"{_error_detail(exc.response)}"
            ) from exc
        except (httpx.HTTPError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise ProviderError(f"ollama request failed: {type(exc).__name__}") from exc
        if not isinstance(content, str) or not content.strip():
            raise ProviderError("ollama returned an empty completion")
        return content


def _error_detail(response: httpx.Response) -> str:
    """A short, safe message from a provider error body."""
    try:
        payload = response.json()
    except ValueError:
        return (response.text or "no detail")[:200]
    error = payload.get("error") if isinstance(payload, dict) else None
    message = error.get("message") if isinstance(error, dict) else error
    if not message and isinstance(payload, dict):
        message = payload.get("detail") or payload.get("message")
    return str(message or "no detail")[:200]


def build_provider(settings: ProviderSettings | None = None) -> ModelProvider:
    """Select the configured provider, refusing external use unless opted in."""
    settings = settings or ProviderSettings.from_env()
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


def provider_status(settings: ProviderSettings | None = None) -> dict[str, Any]:
    """Configuration summary that never includes the API key."""
    settings = settings or ProviderSettings.from_env()
    provider = settings.model_provider.strip().lower()
    key_present = bool(settings.groq_api_key)
    external_allowed = settings.allow_external_model
    if provider == "groq":
        ready = external_allowed and key_present
        model = settings.groq_model
        hint = _provider_hint(provider, external_allowed=external_allowed, key_present=key_present)
    elif provider == "ollama":
        ready = True
        model = settings.ollama_model
        hint = ""
    else:
        ready = False
        model = ""
        hint = "AIOS_MODEL_PROVIDER must be groq or ollama"
    return {
        "provider": provider,
        "external": provider == "groq",
        "external_allowed": external_allowed,
        "configured": settings.groq_enabled if provider == "groq" else provider == "ollama",
        "key_present": key_present,
        "ready": ready,
        "hint": hint,
        "model": model,
    }


def _provider_hint(provider: str, *, external_allowed: bool, key_present: bool) -> str:
    if provider == "groq":
        if not external_allowed:
            return "External model use is disabled: set AIOS_ALLOW_EXTERNAL_MODEL=true"
        if not key_present:
            return "AIOS_GROQ_API_KEY is not set"
    return ""


__all__ = [
    "ChatMessage",
    "GroqProvider",
    "ModelProvider",
    "OllamaProvider",
    "ProviderError",
    "ProviderSettings",
    "build_provider",
    "provider_status",
]
