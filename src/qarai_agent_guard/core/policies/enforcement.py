from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from qarai_agent_guard.core.exceptions import AgentGuardViolation
from qarai_agent_guard.core.guards import AgentGuard
from qarai_agent_guard.core.logger import logger
from qarai_agent_guard.core.schemas import (
    Action,
    EnforcementResult,
    PolicyDecision,
    Severity,
    SourceClass,
)


class PolicyExecutor:
    """Central enforcement engine for AgentGuard decisions.

    Transform a PolicyDecision into security side-effects.
    The actions are ALLOW, WARN, REDACT, BLOCK, or QUARANTINE.

    This executor standardizes enforcement logic across core guards and
    external framework integrations, for example LangChain and CrewAI.
    It offers customization options such as callbacks, custom loggers, and
    configurable violation behavior.
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
            guard: Optional AgentGuard instance.
                The guard is used for redaction and event emission.
            quarantine_handler: Optional callback for QUARANTINE action.
                Called with the source, content, and decision.
            on_violation: Optional callback for a policy violation.
                It applies to BLOCK, QUARANTINE, redaction failure, and
                unrecognized action.
                Called with the source, decision, and content.
            on_warn: Optional callback for WARN action.
                Called with the source, decision, and content.
            raise_on_violation: If True (default), policy violations raise an
                AgentGuardViolation exception. If False, the enforcement
                returns a result with blocked set to True.
            emit_events: If True (default), the guard emits telemetry events
                when available.
            custom_logger: Optional logger for internal diagnostics.
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
        """Return the count of policy violations handled by this executor."""
        return self._violations

    @property
    def violation_count(self) -> int:
        """Return the violations count.

        This property is an alias for ``violations``.
        """
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
        """Invoke a user callback.

        Fall back to positional arguments if keyword arguments fail.
        """
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
        """Increment the violation counter.

        Invoke the ``on_violation`` callback.
        """
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
        """Emit a telemetry event through the guard.

        Telemetry failure does not crash enforcement.
        """
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
            decision: PolicyDecision object.
                It contains the action and the reason.
            content: The input, output, or tool payload.
            detections: Optional list of detection results for redaction.
            source: Identifier for the content source.

        Returns:
            EnforcementResult: The enforced content, action, and flags.

        Raises:
            AgentGuardViolation: If the action is BLOCK or QUARANTINE,
                if redaction fails, or if the action is unrecognized.
                This exception applies only when ``raise_on_violation``
                is set to True.
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
                        "AgentGuard: redaction failed for source=%s,"
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
                        raise AgentGuardViolation(msg) from exc
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
                    "AgentGuard: redaction requested for source=%s "
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
                    raise AgentGuardViolation(msg)
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
                raise AgentGuardViolation(msg)
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
                        raise AgentGuardViolation(msg) from exc
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
                raise AgentGuardViolation(msg)
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
            raise AgentGuardViolation(msg)
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
