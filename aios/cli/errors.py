"""Friendly errors and stable exit codes.

The CLI never shows a traceback. Every failure becomes a short message plus a
next step, and the process exits with one of the documented codes.
"""

from __future__ import annotations

EXIT_OK = 0
EXIT_GENERAL = 1
EXIT_USAGE = 2
EXIT_DENIED = 3
EXIT_UNAVAILABLE = 4


class CliError(Exception):
    """A failure the operator can act on."""

    exit_code = EXIT_GENERAL

    def __init__(
        self,
        message: str,
        *,
        next_step: str | None = None,
        detail: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.next_step = next_step
        self.detail = detail


class UsageError(CliError):
    exit_code = EXIT_USAGE


class DeniedError(CliError):
    exit_code = EXIT_DENIED

    def __init__(self, message: str, *, next_step: str | None = None, detail: str | None = None):
        super().__init__(message, next_step=next_step, detail=detail)


class ServiceUnavailable(CliError):
    exit_code = EXIT_UNAVAILABLE


def api_unreachable(api_url: str, cause: object | None = None) -> ServiceUnavailable:
    detail = f" ({type(cause).__name__})" if cause is not None else ""
    return ServiceUnavailable(
        f"Cannot reach the AIOS core at {api_url}{detail}.",
        next_step="Start it with: aios-core serve   (or check AIOS_API_URL)",
    )


def api_timeout(api_url: str, timeout_s: float) -> ServiceUnavailable:
    return ServiceUnavailable(
        f"The AIOS core at {api_url} did not answer within {timeout_s:g}s.",
        next_step="Check that the core is running and not blocked; retry with --watch 0.",
    )


def unexpected_response(path: str) -> ServiceUnavailable:
    return ServiceUnavailable(
        f"The AIOS core returned an unexpected response from {path}.",
        next_step="Run `aios status` and check the core version and logs.",
    )


def policy_unavailable() -> ServiceUnavailable:
    return ServiceUnavailable(
        "The policy engine (OPA) is unavailable, so AIOS is failing closed.",
        next_step="Start OPA or check `opa version`, then retry.",
    )


def model_unavailable(cause: object | None = None) -> CliError:
    detail = f" ({type(cause).__name__})" if cause is not None else ""
    return CliError(
        f"The local model could not answer{detail}.",
        next_step=(
            "Start Ollama, pull the configured model, and retry: "
            "`ollama serve` / `ollama pull qwen2.5:3b-instruct-q4_K_M`"
        ),
    )


__all__ = [
    "CliError",
    "DeniedError",
    "EXIT_DENIED",
    "EXIT_GENERAL",
    "EXIT_OK",
    "EXIT_UNAVAILABLE",
    "EXIT_USAGE",
    "ServiceUnavailable",
    "UsageError",
    "api_timeout",
    "api_unreachable",
    "model_unavailable",
    "policy_unavailable",
    "unexpected_response",
]
