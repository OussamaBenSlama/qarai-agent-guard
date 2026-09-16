from __future__ import annotations

import logging
from typing import Any

import pytest

from qarai_agent_guard import (
    Action,
    AgentGuard,
    AgentGuardViolation,
    PolicyDecision,
    PolicyExecutor,
)
from qarai_agent_guard.core.exceptions import GuardError
from qarai_agent_guard.core.schemas.detection import DetectionResult

from .conftest import (
    PII_PAYLOAD,
    PROMPT_INJECTION_PAYLOAD,
    SAFE_PAYLOAD,
    SECRET_PAYLOAD,
)


def test_enforce_allow_returns_unmodified_content(executor: PolicyExecutor):
    decision = PolicyDecision(action=Action.ALLOW, reason="Payload clean")
    result = executor.enforce(
        decision=decision,
        content=SAFE_PAYLOAD,
        source="test.allow",
    )
    assert result.action == Action.ALLOW
    assert result.content == SAFE_PAYLOAD
    assert result.blocked is False
    assert result.redacted is False
    assert executor.violations == 0
    assert executor.violation_count == 0


def test_enforce_warn_returns_content_and_emits_event(agent_guard: AgentGuard):
    warn_calls: list[tuple[str, PolicyDecision, Any]] = []

    def on_warn(source: str, decision: PolicyDecision, content: Any) -> None:
        warn_calls.append((source, decision, content))

    executor = PolicyExecutor(agent_guard, on_warn=on_warn)
    decision = PolicyDecision(action=Action.WARN, reason="Low severity finding")
    result = executor.enforce(
        decision=decision,
        content=PII_PAYLOAD,
        source="test.warn",
    )
    assert result.action == Action.WARN
    assert result.content == PII_PAYLOAD
    assert executor.violations == 0
    assert len(warn_calls) == 1
    assert warn_calls[0][0] == "test.warn"
    assert len(agent_guard.events) == 1
    assert agent_guard.events[0].action == Action.WARN


def test_enforce_warn_swallows_callback_exception(agent_guard: AgentGuard):
    def bad_on_warn(*args: Any, **kwargs: Any) -> None:
        raise ValueError("warn callback exploded")

    executor = PolicyExecutor(agent_guard, on_warn=bad_on_warn)
    decision = PolicyDecision(action=Action.WARN, reason="Warn error handling")
    result = executor.enforce(
        decision=decision,
        content=SAFE_PAYLOAD,
        source="test.warn.fail",
    )
    assert result.content == SAFE_PAYLOAD


def test_enforce_redact_sanitizes_pii_content(agent_guard: AgentGuard):
    executor = PolicyExecutor(agent_guard)
    decision, detections = agent_guard.inspect_with_results(
        key="test_pii",
        value=PII_PAYLOAD,
        operation="input",
    )
    redact_decision = PolicyDecision(action=Action.REDACT, reason="PII detected")
    result = executor.enforce(
        decision=redact_decision,
        content=PII_PAYLOAD,
        detections=detections,
        source="test.redact",
    )
    assert result.action == Action.REDACT
    assert result.redacted is True
    assert "oussama@test.com" not in result.content
    assert "[REDACTED:email]" in result.content
    assert executor.violations == 0


def test_enforce_redact_without_detections_passes_through(executor: PolicyExecutor):
    decision = PolicyDecision(action=Action.REDACT, reason="No detections available")
    result = executor.enforce(
        decision=decision,
        content=SECRET_PAYLOAD,
        detections=None,
        source="test.redact.nodetect",
    )
    assert result.action == Action.REDACT
    assert result.redacted is False
    assert result.content == SECRET_PAYLOAD


def test_enforce_redact_failure_falls_back_to_block(
    agent_guard: AgentGuard,
    monkeypatch: pytest.MonkeyPatch,
):
    executor = PolicyExecutor(agent_guard)
    decision = PolicyDecision(
        action=Action.REDACT, reason="Redaction execution failure"
    )
    detections = [DetectionResult(detector="pii", matched=True, message="Found PII")]

    def mock_apply_redactions(*args: Any, **kwargs: Any) -> str:
        raise RuntimeError("Redaction engine error")

    monkeypatch.setattr(agent_guard, "apply_redactions", mock_apply_redactions)

    with pytest.raises(AgentGuardViolation, match="could not safely redact"):
        executor.enforce(
            decision=decision,
            content=PII_PAYLOAD,
            detections=detections,
            source="test.redact.crash",
        )
    assert executor.violations == 1


def test_enforce_redact_without_guard_instance_blocks():
    executor = PolicyExecutor(guard=None)
    decision = PolicyDecision(action=Action.REDACT, reason="Guard instance missing")
    detections = [DetectionResult(detector="pii", matched=True, message="Found PII")]

    with pytest.raises(AgentGuardViolation, match="no guard instance provided"):
        executor.enforce(
            decision=decision,
            content=SECRET_PAYLOAD,
            detections=detections,
            source="test.redact.noguard",
        )
    assert executor.violations == 1


def test_enforce_block_raises_agent_guard_violation(agent_guard: AgentGuard):
    violations: list[tuple[str, PolicyDecision, Any]] = []

    def on_violation(source: str, decision: PolicyDecision, content: Any) -> None:
        violations.append((source, decision, content))

    executor = PolicyExecutor(agent_guard, on_violation=on_violation)
    decision = PolicyDecision(
        action=Action.BLOCK,
        reason="Prompt injection payload detected",
    )

    with pytest.raises(AgentGuardViolation, match="AgentGuard blocked execution"):
        executor.enforce(
            decision=decision,
            content=PROMPT_INJECTION_PAYLOAD,
            source="test.block",
        )
    assert executor.violations == 1
    assert len(violations) == 1
    assert violations[0][0] == "test.block"
    assert violations[0][1] == decision
    assert violations[0][2] == PROMPT_INJECTION_PAYLOAD


def test_enforce_block_with_raise_on_violation_false(agent_guard: AgentGuard):
    executor = PolicyExecutor(agent_guard, raise_on_violation=False)
    decision = PolicyDecision(action=Action.BLOCK, reason="Non-raising block mode")

    result = executor.enforce(
        decision=decision,
        content=PROMPT_INJECTION_PAYLOAD,
        source="test.block.noraise",
    )
    assert result.action == Action.BLOCK
    assert result.blocked is True
    assert executor.violations == 1


def test_quarantine_handler_called_successfully(agent_guard: AgentGuard):
    quarantined: list[dict[str, Any]] = []

    def quarantine_handler(source: str, content: Any, decision: PolicyDecision) -> None:
        quarantined.append({"source": source, "content": content, "decision": decision})

    executor = PolicyExecutor(agent_guard, quarantine_handler=quarantine_handler)
    decision = PolicyDecision(
        action=Action.QUARANTINE,
        reason="Quarantine sensitive payload",
    )

    result = executor.enforce(
        decision=decision,
        content=SECRET_PAYLOAD,
        source="test.quarantine",
    )
    assert result.action == Action.QUARANTINE
    assert result.blocked is True
    assert len(quarantined) == 1
    assert quarantined[0]["source"] == "test.quarantine"
    assert quarantined[0]["content"] == SECRET_PAYLOAD
    assert executor.violations == 1


def test_quarantine_handler_raises_produces_violation(agent_guard: AgentGuard):
    def bad_quarantine_handler(
        source: str, content: Any, decision: PolicyDecision
    ) -> None:
        raise RuntimeError("Quarantine handler processing failed")

    executor = PolicyExecutor(agent_guard, quarantine_handler=bad_quarantine_handler)
    decision = PolicyDecision(
        action=Action.QUARANTINE,
        reason="Faulty quarantine handler",
    )

    with pytest.raises(AgentGuardViolation, match="Content quarantined"):
        executor.enforce(
            decision=decision,
            content=SECRET_PAYLOAD,
            source="test.quarantine.fail",
        )
    assert executor.violations == 1


def test_quarantine_no_handler_raises_violation(agent_guard: AgentGuard):
    executor = PolicyExecutor(agent_guard, quarantine_handler=None)
    decision = PolicyDecision(
        action=Action.QUARANTINE,
        reason="Unconfigured quarantine handler",
    )

    with pytest.raises(AgentGuardViolation, match="no quarantine_handler configured"):
        executor.enforce(
            decision=decision,
            content=SECRET_PAYLOAD,
            source="test.quarantine.nohandler",
        )
    assert executor.violations == 1


def test_enforce_decision_alias(executor: PolicyExecutor):
    decision = PolicyDecision(action=Action.ALLOW, reason="Clean payload")
    result = executor.enforce_decision(
        decision=decision,
        content=SAFE_PAYLOAD,
        source="test.alias",
    )
    assert result.action == Action.ALLOW
    assert result.content == SAFE_PAYLOAD


def test_custom_logger_and_on_violation_error_swallowed(
    agent_guard: AgentGuard,
    caplog: pytest.CapLogFixture,
):
    custom_log = logging.getLogger("qarai.test.enforcement")

    def bad_violation_callback(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("Violation callback exception")

    executor = PolicyExecutor(
        agent_guard,
        on_violation=bad_violation_callback,
        custom_logger=custom_log,
    )
    decision = PolicyDecision(action=Action.BLOCK, reason="Testing custom logger")

    with caplog.at_level(logging.ERROR, logger="qarai.test.enforcement"):
        with pytest.raises(AgentGuardViolation):
            executor.enforce(
                decision=decision,
                content=PROMPT_INJECTION_PAYLOAD,
                source="test.custom_logger",
            )

    assert "on_violation callback raised an error" in caplog.text


def test_unknown_action_raises_guard_error(executor: PolicyExecutor):
    decision = PolicyDecision(
        action="unknown",
        reason="Unsupported action",
    )

    with pytest.raises(GuardError):
        executor.enforce(
            decision=decision,
            content=SAFE_PAYLOAD,
            source="test.unknown",
        )
