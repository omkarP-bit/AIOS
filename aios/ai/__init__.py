"""AI runtime: provider, context, and proposal planner.

Nothing in this package authorizes anything. It produces a proposal; the
security engine decides whether that proposal may run.
"""

from aios.ai.context import CONTEXT_NOTICE, build_snapshot, render_snapshot
from aios.ai.planner import (
    SYSTEM_PROMPT,
    Planner,
    PlanResult,
    ProposalError,
    build_user_prompt,
    parse_proposal,
    plan_to_dict,
    prompt_hash,
)
from aios.ai.providers import (
    ChatMessage,
    GroqProvider,
    ModelProvider,
    OllamaProvider,
    ProviderError,
    build_provider,
    provider_status,
)

__all__ = [
    "CONTEXT_NOTICE",
    "ChatMessage",
    "GroqProvider",
    "ModelProvider",
    "OllamaProvider",
    "PlanResult",
    "Planner",
    "ProposalError",
    "ProviderError",
    "SYSTEM_PROMPT",
    "build_provider",
    "build_snapshot",
    "build_user_prompt",
    "parse_proposal",
    "plan_to_dict",
    "prompt_hash",
    "provider_status",
    "render_snapshot",
]
