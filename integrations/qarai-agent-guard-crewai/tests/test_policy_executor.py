from __future__ import annotations

import pytest
from qarai_agent_guard import AgentGuardViolation, PolicyExecutor
from qarai_agent_guard.core.schemas import Action, PolicyDecision

from .conftest import (
    CLEAN_TEXT,
    PII_TEXT,
    PROMPT_INJECTION_TEXT,
    SECRET_TEXT,
)


def _check_and_enforce(
    executor: PolicyExecutor, text: str, source: str = "test"
) -> object:
    """Run the guard's check pipeline, then enforce the decision."""
    decision, detections = executor.guard.check(
        key="test_key",
        value=text,
        operation="write",
    )
    return executor.enforce(
        decision=decision,
        content=text,
        detections=detections,
        source=source,
    )


# --- ALLOW ---------------------------------------------------------


def test_enforce_allow_clean_content(guard):
    executor = PolicyExecutor(guard=guard)
    result = _check_and_enforce(executor, CLEAN_TEXT)

    assert result.action == Action.ALLOW
    assert result.content == CLEAN_TEXT
    assert result.redacted is False
    assert result.blocked is False
    assert executor.violations == 0


def test_enforce_allow_does_not_increment_violations(guard):
    executor = PolicyExecutor(guard=guard)
    _check_and_enforce(executor, CLEAN_TEXT)
    _check_and_enforce(executor, "Another safe sentence.")
    assert executor.violations == 0


# --- WARN ----------------------------------------------------------


def test_enforce_warn_returns_original_content(guard):
    """Force a WARN decision and verify content is unchanged."""
    executor = PolicyExecutor(guard=guard)
    decision = PolicyDecision(action=Action.WARN, reason="low severity match")
    result = executor.enforce(
        decision=decision,
        content=CLEAN_TEXT,
        detections=None,
        source="test.warn",
    )
    assert result.action == Action.WARN
    assert result.content == CLEAN_TEXT
    assert executor.violations == 0


def test_email_match_warns_with_default_policy(guard):
    """A low-severity email match produces a WARN under the default policy."""
    executor = PolicyExecutor(guard=guard)
    result = _check_and_enforce(executor, "Contact alice@example.com for details.")

    assert result.action == Action.WARN
    assert result.blocked is False
    assert executor.violations == 0


# --- BLOCK ---------------------------------------------------------


def test_enforce_block_raises_on_prompt_injection(guard):
    executor = PolicyExecutor(guard=guard)
    with pytest.raises(AgentGuardViolation, match="blocked"):
        _check_and_enforce(executor, PROMPT_INJECTION_TEXT)


def test_enforce_block_increments_violation_count(guard):
    executor = PolicyExecutor(guard=guard)
    try:
        _check_and_enforce(executor, PROMPT_INJECTION_TEXT)
    except AgentGuardViolation:
        pass
    assert executor.violations == 1


def test_enforce_block_on_secrets(guard):
    executor = PolicyExecutor(guard=guard)
    with pytest.raises(AgentGuardViolation):
        _check_and_enforce(executor, SECRET_TEXT)


def test_block_with_raise_on_violation_false_returns_result(guard):
    executor = PolicyExecutor(guard=guard, raise_on_violation=False)
    result = _check_and_enforce(executor, PROMPT_INJECTION_TEXT)

    assert result.action == Action.BLOCK
    assert result.blocked is True
    assert executor.violations == 1


# --- REDACT --------------------------------------------------------


def test_enforce_redact_pii_sanitises_content(guard):
    executor = PolicyExecutor(guard=guard)
    result = _check_and_enforce(executor, PII_TEXT)

    assert result.action == Action.REDACT
    assert result.redacted is True
    assert "GB29NWBK60161331926819" not in result.content
    assert executor.violations == 0


def test_enforce_redact_without_detections_passes_through(guard):
    """REDACT decision but no detections → content unchanged."""
    executor = PolicyExecutor(guard=guard)
    decision = PolicyDecision(action=Action.REDACT, reason="medium match")
    result = executor.enforce(
        decision=decision,
        content=CLEAN_TEXT,
        detections=[],
        source="test.redact.empty",
    )
    assert result.content == CLEAN_TEXT
    assert result.action == Action.REDACT
    assert result.redacted is False


# --- QUARANTINE ----------------------------------------------------


def test_quarantine_handler_called(quarantine_guard):
    calls = []

    def handler(*, source, content, decision):
        calls.append({"source": source, "content": content, "decision": decision})

    executor = PolicyExecutor(
        guard=quarantine_guard,
        quarantine_handler=handler,
    )
    decision, detections = quarantine_guard.check(
        key="test_key",
        value=PROMPT_INJECTION_TEXT,
        operation="write",
    )
    assert decision.action == Action.QUARANTINE

    result = executor.enforce(
        decision=decision,
        content=PROMPT_INJECTION_TEXT,
        detections=detections,
        source="test.quarantine",
    )
    assert len(calls) == 1
    assert calls[0]["source"] == "test.quarantine"
    assert result.blocked is True
    assert executor.violations == 1


def test_quarantine_handler_raises_produces_violation(quarantine_guard):
    def bad_handler(*, source, content, decision):
        raise RuntimeError("handler boom")

    executor = PolicyExecutor(
        guard=quarantine_guard,
        quarantine_handler=bad_handler,
    )
    decision, detections = quarantine_guard.check(
        key="test_key",
        value=PROMPT_INJECTION_TEXT,
        operation="write",
    )
    with pytest.raises(AgentGuardViolation, match="quarantined"):
        executor.enforce(
            decision=decision,
            content=PROMPT_INJECTION_TEXT,
            detections=detections,
            source="test.quarantine.fail",
        )


def test_quarantine_no_handler_falls_through(quarantine_guard):
    """No quarantine_handler set → falls through to a blocking violation."""
    executor = PolicyExecutor(guard=quarantine_guard, quarantine_handler=None)
    decision, detections = quarantine_guard.check(
        key="test_key",
        value=PROMPT_INJECTION_TEXT,
        operation="write",
    )

    with pytest.raises(AgentGuardViolation, match="quarantined"):
        executor.enforce(
            decision=decision,
            content=PROMPT_INJECTION_TEXT,
            detections=detections,
            source="test.quarantine.nohandler",
        )


# --- callbacks ----------------------------------------------------


def test_on_violation_receives_context(guard):
    calls = []

    def recorder(*, source, decision, content):
        calls.append({"source": source, "decision": decision, "content": content})

    executor = PolicyExecutor(guard=guard, on_violation=recorder)
    with pytest.raises(AgentGuardViolation):
        _check_and_enforce(executor, PROMPT_INJECTION_TEXT, source="callback.test")

    assert len(calls) == 1
    assert calls[0]["source"] == "callback.test"
    assert calls[0]["decision"].action == Action.BLOCK
    assert calls[0]["content"] == PROMPT_INJECTION_TEXT


def test_on_violation_exception_is_swallowed(guard):
    """A crashing on_violation must not prevent the BLOCK from being raised."""

    def crasher(*, source, decision, content):
        raise RuntimeError("callback exploded")

    executor = PolicyExecutor(guard=guard, on_violation=crasher)
    with pytest.raises(AgentGuardViolation):
        _check_and_enforce(executor, PROMPT_INJECTION_TEXT)


def test_on_warn_callback_receives_context(guard):
    calls = []

    def recorder(*, source, decision, content):
        calls.append({"source": source, "content": content})

    executor = PolicyExecutor(guard=guard, on_warn=recorder)
    _check_and_enforce(executor, "Contact alice@example.com for details.")

    assert len(calls) == 1
    assert calls[0]["source"] == "test"


# --- properties ----------------------------------------------------


def test_violations_and_violation_count_are_aliases(guard):
    executor = PolicyExecutor(guard=guard, raise_on_violation=False)
    _check_and_enforce(executor, PROMPT_INJECTION_TEXT)
    assert executor.violations == 1
    assert executor.violation_count == 1
