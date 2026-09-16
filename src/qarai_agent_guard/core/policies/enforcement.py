from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from qarai_agent_guard.core.exceptions import AgentGuardViolation
from qarai_agent_guard.core.guards.agent_guard import AgentGuard
from qarai_agent_guard.core.logger import logger
from qarai_agent_guard.core.schemas.events import Action, Severity, SourceClass
from qarai_agent_guard.core.schemas.policy import EnforcementResult, PolicyDecision


class PolicyExecutor:
    """Central policy enforcement engine for AgentGuard decisions.

    Transforms a PolicyDecision into actual security side-effects: ALLOW,
    WARN, REDACT, BLOCK, or QUARANTINE.

    This executor standardizes enforcement logic across core guards and external
    framework integrations (e.g., LangChain, CrewAI), while offering robust
    customization options like callbacks, custom loggers, and configurable
    violation behavior.
    """

    def __init__(
        self,
        guard: AgentGuard | None = None,
        *,
        quarantine_handler: Callable[..., None] | None = None,
        on_violation: Callable[..., None] | None = None,
        on_warn: Callable[..., None] | None = None,
        raise_on_violation: bool = True,
        emit_events: bool = True,
        custom_logger: logging.Logger | None = None,
    ) -> None:
        """Initialize the policy executor.

        Args:
            guard: Optional AgentGuard instance used for redaction and event emission.
            quarantine_handler: Optional callback invoked when action is QUARANTINE.
                Called with (source=..., content=..., decision=...).
            on_violation: Optional callback invoked when a policy violation occurs
                (BLOCK, QUARANTINE, redaction failure, unrecognized action).
                Called with (source=..., decision=..., content=...).
            on_warn: Optional callback invoked when action is WARN.
                Called with (source=..., decision=..., content=...).
            raise_on_violation: If True (default), policy violations raise an
                AgentGuardViolation exception. If False, returns EnforcementResult
                with blocked=True.
            emit_events: If True (default), telemetry events are emitted via guard
                when available.
            custom_logger: Optional logger override for internal diagnostic logging.
        """
        self.guard = guard
        self.quarantine_handler = quarantine_handler
        self.on_violation = on_violation
        self.on_warn = on_warn
        self.raise_on_violation = raise_on_violation
        self.emit_events = emit_events
        self.logger = custom_logger or logger
        self._violations = 0

    @property
    def violations(self) -> int:
        """Return total count of policy violations handled by this executor."""
        return self._violations

    @property
    def violation_count(self) -> int:
        """Alias for violations property."""
        return self._violations

    def _call_callback(
        self,
        callback: Callable[..., Any],
        *,
        source: str,
        decision: PolicyDecision,
        content: Any,
        log_label: str,
        swallow_exceptions: bool = True,
    ) -> Any:
        """Helper to invoke user callbacks with keyword argument fallback."""
        try:
            return callback(source=source, decision=decision, content=content)
        except TypeError:
            try:
                return callback(source, decision, content)
            except Exception:
                if not swallow_exceptions:
                    raise
                self.logger.exception(
                    "AgentGuard: %s callback raised an error", log_label
                )
        except Exception:
            if not swallow_exceptions:
                raise
            self.logger.exception("AgentGuard: %s callback raised an error", log_label)

    def _notify_violation(
        self,
        *,
        source: str,
        decision: PolicyDecision,
        content: Any,
    ) -> None:
        """Increment violation counter and invoke on_violation callback safely."""
        self._violations += 1
        if self.on_violation is not None:
            self._call_callback(
                self.on_violation,
                source=source,
                decision=decision,
                content=content,
                log_label="on_violation",
                swallow_exceptions=True,
            )

    def _emit_safe(self, **kwargs: Any) -> None:
        """Emit telemetry event via guard without letting telemetry
        failure crash enforcement."""
        if not self.emit_events or self.guard is None:
            return
        try:
            if hasattr(self.guard, "_emit_event") and callable(self.guard._emit_event):
                self.guard._emit_event(**kwargs)
        except Exception:
            self.logger.exception("AgentGuard: failed to emit event")

    def enforce(
        self,
        *,
        decision: PolicyDecision,
        content: Any,
        detections: list[Any] | None = None,
        source: str = "unknown",
    ) -> EnforcementResult:
        """Enforce a policy decision against content.

        Args:
            decision: PolicyDecision object containing the action and reason.
            content: The input, output, or tool payload to enforce against.
            detections: Optional list of detection results for redaction.
            source: Identifier describing the source of the content.

        Returns:
            EnforcementResult containing the enforced content, action, and flags.

        Raises:
            AgentGuardViolation: If action is BLOCK, QUARANTINE,
                redaction failure, or unrecognized action,
                and raise_on_violation is True.
        """
        action = decision.action

        if action == Action.ALLOW:
            return EnforcementResult(
                content=content,
                action=action,
                blocked=False,
                redacted=False,
                decision=decision,
                detections=detections,
                source=source,
            )

        if action == Action.WARN:
            self._emit_safe(
                detector="middleware",
                severity=Severity.INFO,
                action=action,
                key=source,
                message=decision.reason,
                operation="middleware",
                source_class=SourceClass.UNKNOWN,
                metadata={"source": source, "reason": decision.reason},
            )
            if self.on_warn is not None:
                self._call_callback(
                    self.on_warn,
                    source=source,
                    decision=decision,
                    content=content,
                    log_label="on_warn",
                    swallow_exceptions=True,
                )
            return EnforcementResult(
                content=content,
                action=action,
                blocked=False,
                redacted=False,
                decision=decision,
                detections=detections,
                source=source,
            )

        if action == Action.REDACT:
            if not detections:
                return EnforcementResult(
                    content=content,
                    action=action,
                    blocked=False,
                    redacted=False,
                    decision=decision,
                    detections=detections,
                    source=source,
                )
            if self.guard is not None:
                try:
                    redacted_content = self.guard.apply_redactions(
                        content,
                        detections=detections,
                    )
                    return EnforcementResult(
                        content=redacted_content,
                        action=action,
                        blocked=False,
                        redacted=True,
                        decision=decision,
                        detections=detections,
                        source=source,
                    )
                except Exception as exc:
                    self.logger.exception(
                        "AgentGuard: redaction failed for source=%s,",
                        "falling back to block",
                        source,
                    )
                    self._notify_violation(
                        source=source, decision=decision, content=content
                    )
                    msg = (
                        f"AgentGuard could not safely redact content from {source} "
                        f"and blocked it instead. Reason: {decision.reason}"
                    )
                    if self.raise_on_violation:
                        raise AgentGuardViolation(
                            msg,
                            source=source,
                            decision=decision,
                            content=content,
                        ) from exc
                    return EnforcementResult(
                        content=content,
                        action=Action.BLOCK,
                        blocked=True,
                        redacted=False,
                        decision=decision,
                        detections=detections,
                        source=source,
                    )
            else:
                self.logger.warning(
                    "AgentGuard: redaction requested for source=%s",
                    "but no AgentGuard instance provided; blocking",
                    source,
                )
                self._notify_violation(
                    source=source, decision=decision, content=content
                )
                msg = (
                    f"AgentGuard could not redact content from {source} "
                    f"(no guard instance provided) and blocked it instead."
                    f"Reason: {decision.reason}"
                )
                if self.raise_on_violation:
                    raise AgentGuardViolation(
                        msg,
                        source=source,
                        decision=decision,
                        content=content,
                    )
                return EnforcementResult(
                    content=content,
                    action=Action.BLOCK,
                    blocked=True,
                    redacted=False,
                    decision=decision,
                    detections=detections,
                    source=source,
                )

        if action == Action.BLOCK:
            self._notify_violation(source=source, decision=decision, content=content)
            msg = (
                f"AgentGuard blocked execution.\n\n"
                f"Source:\n{source}\n\n"
                f"Reason:\n{decision.reason}"
            )
            if self.raise_on_violation:
                raise AgentGuardViolation(
                    msg,
                    source=source,
                    decision=decision,
                    content=content,
                )
            return EnforcementResult(
                content=content,
                action=action,
                blocked=True,
                redacted=False,
                decision=decision,
                detections=detections,
                source=source,
            )

        if action == Action.QUARANTINE:
            self._notify_violation(source=source, decision=decision, content=content)
            if self.quarantine_handler is not None:
                try:
                    self._call_callback(
                        self.quarantine_handler,
                        source=source,
                        decision=decision,
                        content=content,
                        log_label="quarantine_handler",
                        swallow_exceptions=False,
                    )
                    return EnforcementResult(
                        content=content,
                        action=action,
                        blocked=True,
                        redacted=False,
                        decision=decision,
                        detections=detections,
                        source=source,
                    )
                except Exception as exc:
                    self.logger.exception("AgentGuard: quarantine_handler raised")
                    msg = (
                        f"Content quarantined by AgentGuard.\n\n"
                        f"Source:\n{source}\n\n"
                        f"Reason:\n{decision.reason}"
                    )
                    if self.raise_on_violation:
                        raise AgentGuardViolation(
                            msg,
                            source=source,
                            decision=decision,
                            content=content,
                        ) from exc
                    return EnforcementResult(
                        content=content,
                        action=action,
                        blocked=True,
                        redacted=False,
                        decision=decision,
                        detections=detections,
                        source=source,
                    )

            msg = (
                "Content quarantined by AgentGuard "
                "(no quarantine_handler configured).\n\n"
                f"Source:\n{source}\n\nReason:\n{decision.reason}"
            )
            if self.raise_on_violation:
                raise AgentGuardViolation(
                    msg,
                    source=source,
                    decision=decision,
                    content=content,
                )
            return EnforcementResult(
                content=content,
                action=action,
                blocked=True,
                redacted=False,
                decision=decision,
                detections=detections,
                source=source,
            )

        self.logger.warning(
            "AgentGuard: unrecognized policy action %r; blocking", action
        )
        self._notify_violation(source=source, decision=decision, content=content)
        msg = (
            f"AgentGuard encountered an unrecognized action ({action!r}) for "
            f"source={source} and blocked as a precaution."
        )
        if self.raise_on_violation:
            raise AgentGuardViolation(
                msg,
                source=source,
                decision=decision,
                content=content,
            )
        return EnforcementResult(
            content=content,
            action=action,
            blocked=True,
            redacted=False,
            decision=decision,
            detections=detections,
            source=source,
        )

    def enforce_decision(
        self,
        *,
        decision: PolicyDecision,
        content: Any,
        detections: list[Any] | None = None,
        source: str = "unknown",
    ) -> EnforcementResult:
        """Alias for enforce()."""
        return self.enforce(
            decision=decision,
            content=content,
            detections=detections,
            source=source,
        )
