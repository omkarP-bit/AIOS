"""Test isolation: never read the developer's `.env` or ambient AIOS_* vars.

Provider tests set exactly the variables they need with monkeypatch, so the
suite gives the same result on a laptop configured for Groq and on CI.
"""

from __future__ import annotations

import pytest

MODEL_ENV = (
    "AIOS_MODEL_PROVIDER",
    "AIOS_ALLOW_EXTERNAL_MODEL",
    "AIOS_GROQ_API_KEY",
    "AIOS_GROQ_BASE_URL",
    "AIOS_GROQ_MODEL",
    "AIOS_GROQ_TIMEOUT_S",
    "AIOS_GROQ_MAX_TOKENS",
    "AIOS_GROQ_TEMPERATURE",
    "AIOS_OLLAMA_URL",
    "AIOS_OLLAMA_MODEL",
    "AIOS_OLLAMA_TIMEOUT_S",
)


@pytest.fixture(autouse=True)
def isolate_model_env(monkeypatch):
    for key in MODEL_ENV:
        monkeypatch.delenv(key, raising=False)
    # Stop ProviderSettings.from_env from reading the repository's .env.
    monkeypatch.setattr("aios.ai.env._LOADED", True)
