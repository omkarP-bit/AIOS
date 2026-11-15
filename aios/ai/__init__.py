"""AI runtime: provider, context, and proposal planner.

Nothing in this package authorizes anything. It produces a proposal and posts
it to the Go control core, which decides whether it may run.
"""

from aios.ai.catalog import Catalog, CatalogError
from aios.ai.client import ControlClient, ControlError
from aios.ai.context import CONTEXT_NOTICE, build_snapshot, render_snapshot
from aios.ai.injection import annotation, scan_payload, scan_untrusted
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
from aios.ai.protocol import ActionRequest, new_action_id
from aios.ai.providers import (
    ChatMessage,
    GroqProvider,
    ModelProvider,
    OllamaProvider,
    ProviderError,
    ProviderSettings,
    build_provider,
    provider_status,
)

__all__ = [
    "ActionRequest",
    "CONTEXT_NOTICE",
    "Catalog",
    "CatalogError",
    "ChatMessage",
    "ControlClient",
    "ControlError",
    "GroqProvider",
    "ModelProvider",
    "OllamaProvider",
    "PlanResult",
    "Planner",
    "ProposalError",
    "ProviderError",
    "ProviderSettings",
    "SYSTEM_PROMPT",
    "annotation",
    "build_provider",
    "build_snapshot",
    "build_user_prompt",
    "new_action_id",
    "parse_proposal",
    "plan_to_dict",
    "prompt_hash",
    "provider_status",
    "render_snapshot",
    "scan_payload",
    "scan_untrusted",
]
