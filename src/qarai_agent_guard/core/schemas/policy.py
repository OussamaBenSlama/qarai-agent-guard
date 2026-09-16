from dataclasses import dataclass
from typing import Any

from qarai_agent_guard.core.schemas.events import Action, Severity


@dataclass(slots=True)
class PolicyDecision:
    action: Action
    reason: str = ""


@dataclass(frozen=True, slots=True)
class SeverityRule:
    severities: tuple[Severity, ...]
    action: Action


@dataclass(slots=True)
class EnforcementResult:
    """Outcome of enforcing a policy decision against target content."""

    content: Any
    action: Action
    blocked: bool = False
    redacted: bool = False
    decision: PolicyDecision | None = None
    detections: list[Any] | None = None
    source: str | None = None
