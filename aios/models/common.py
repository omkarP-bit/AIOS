"""Common data model.

Everything that leaves an observer, the gateway, or the security engine is
wrapped in the same envelope so that provenance is never optional and never
inferred from context at the call site.

Shape: ``{source, timestamp, type, data}`` plus trust metadata.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field, model_validator

T = TypeVar("T")


def utcnow() -> datetime:
    return datetime.now(UTC)


class TrustDomain(str, Enum):
    """Trust domains from the security model.

    T0/T1/T2 are inside the boundary. T3 (the AI runtime) is untrusted even
    when it runs locally. T4 is external data and is treated as hostile.
    """

    T0_KERNEL = "T0"
    T1_SECURITY = "T1"
    T2_GATEWAY = "T2"
    T3_AI = "T3"
    T4_EXTERNAL = "T4"


#: What may be trusted based on where the data came from.
TRUSTED_DOMAINS = frozenset(
    {TrustDomain.T0_KERNEL, TrustDomain.T1_SECURITY, TrustDomain.T2_GATEWAY}
)

#: Domains that must never be able to influence authorization on their own.
UNTRUSTED_DOMAINS = frozenset({TrustDomain.T3_AI, TrustDomain.T4_EXTERNAL})


class DataOrigin(str, Enum):
    KERNEL = "kernel"
    SYSFS = "sysfs"
    GATEWAY = "gateway"
    SECURITY = "security"
    POLICY = "policy"
    AI = "ai"
    USER = "user"
    EXTERNAL = "external"
    TOOL = "tool"


#: Origin -> trust domain. An origin always maps to exactly one domain, so
#: provenance cannot be upgraded by a caller that simply picks a friendlier
#: origin string.
ORIGIN_TRUST: dict[DataOrigin, TrustDomain] = {
    DataOrigin.KERNEL: TrustDomain.T0_KERNEL,
    DataOrigin.SYSFS: TrustDomain.T0_KERNEL,
    DataOrigin.GATEWAY: TrustDomain.T2_GATEWAY,
    DataOrigin.SECURITY: TrustDomain.T1_SECURITY,
    DataOrigin.POLICY: TrustDomain.T1_SECURITY,
    DataOrigin.AI: TrustDomain.T3_AI,
    DataOrigin.USER: TrustDomain.T3_AI,
    DataOrigin.EXTERNAL: TrustDomain.T4_EXTERNAL,
    DataOrigin.TOOL: TrustDomain.T4_EXTERNAL,
}


class Observation(BaseModel, Generic[T]):
    """A single unit of observed system state.

    ``data`` is the payload. Everything outside ``data`` is metadata that
    describes where the payload came from and how much it should be trusted.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: str = Field(description="Concrete producer, e.g. 'procfs:/proc/meminfo'")
    origin: DataOrigin = Field(description="Coarse producer class")
    trust_domain: TrustDomain = Field(
        default=None,  # type: ignore[assignment]
        description="Trust domain derived from origin; not caller-settable",
    )
    timestamp: datetime = Field(default_factory=utcnow)
    type: str = Field(description="Observation type, matches the action namespace")
    data: T

    @model_validator(mode="before")
    @classmethod
    def _derive_trust_domain(cls, values: Any) -> Any:
        """Refuse a caller-supplied trust domain, then derive it from origin.

        Without this, any component could label its own output T1 to get its
        claims treated as policy input. The domain is a property of where the
        data came from, not something the producer asserts about itself.
        """
        if not isinstance(values, dict):
            return values
        if "trust_domain" in values and values["trust_domain"] is not None:
            raise ValueError(
                "trust_domain is derived from origin and cannot be supplied directly"
            )
        origin = values.get("origin")
        if isinstance(origin, DataOrigin):
            values = {**values, "trust_domain": ORIGIN_TRUST[origin]}
        elif isinstance(origin, str):
            try:
                values = {**values, "trust_domain": ORIGIN_TRUST[DataOrigin(origin)]}
            except ValueError as exc:
                raise ValueError(f"unknown origin: {origin!r}") from exc
        return values

    @model_validator(mode="after")
    def _require_derived_domain(self) -> Observation[T]:
        if self.trust_domain is None:
            raise ValueError("origin is required to derive trust_domain")
        return self

    @classmethod
    def build(
        cls,
        *,
        type: str,
        source: str,
        origin: DataOrigin,
        data: T,
        timestamp: datetime | None = None,
    ) -> Observation[T]:
        """Construct an envelope. The trust domain is derived, never passed in.

        A caller that wants to claim trusted data from an untrusted origin has
        to go through this and cannot; the mapping is fixed above.
        """
        return cls(
            source=source,
            origin=origin,
            timestamp=timestamp or utcnow(),
            type=type,
            data=data,
        )

    @property
    def is_trusted(self) -> bool:
        return self.trust_domain in TRUSTED_DOMAINS


class EnvelopeError(ValueError):
    """Raised when an envelope would misstate provenance."""
