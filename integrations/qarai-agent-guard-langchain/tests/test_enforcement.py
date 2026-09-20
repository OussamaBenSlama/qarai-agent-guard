from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from langchain_core.messages import AIMessage, HumanMessage
from qarai_agent_guard import AgentGuardViolation
from qarai_agent_guard.core.schemas import Action

from qarai_agent_guard_langchain.middleware import AgentGuardMiddleware

from .conftest import (
    CLEAN_TEXT,
    PII_CARD_TEXT,
    PII_EMAIL_TEXT,
    PII_IBAN_TEXT,
    PROMPT_INJECTION_TEXT,
)

# --- violation counter --------------------------------------------


def test_increments_on_block(middleware):
    with pytest.raises(AgentGuardViolation):
        middleware.before_model(
            {"messages": [HumanMessage(content=PROMPT_INJECTION_TEXT)]},
            runtime=None,
        )

    assert middleware.violation_count == 1


def test_increments_across_entry_points(middleware):
    with pytest.raises(AgentGuardViolation):
        middleware.after_model(
            {"messages": [AIMessage(content=PROMPT_INJECTION_TEXT)]},
            runtime=None,
        )
    assert middleware.violation_count == 1

    with pytest.raises(AgentGuardViolation):
        middleware.before_model(
            {"messages": [HumanMessage(content=PROMPT_INJECTION_TEXT)]},
            runtime=None,
        )
    assert middleware.violation_count == 2


# --- enforcement actions ------------------------------------------


def test_allow_passes_clean_through(middleware):
    result = middleware.before_model(
        {"messages": [HumanMessage(content=CLEAN_TEXT)]},
        runtime=None,
    )
    assert result is None
    assert middleware.violation_count == 0


def test_warn_does_not_raise_and_records_event(middleware):
    result = middleware.before_model(
        {"messages": [HumanMessage(content=PII_EMAIL_TEXT)]},
        runtime=None,
    )

    assert result is None
    assert middleware.violation_count == 0

    warn_events = [e for e in middleware.guard.events if e.action == Action.WARN]
    assert warn_events
    assert warn_events[0].detector in {"pii", "middleware"}


def test_redact_replaces_sensitive_content(middleware):
    message = HumanMessage(content=PII_IBAN_TEXT)
    middleware.before_model({"messages": [message]}, runtime=None)

    assert "GB29NWBK60161331926819" not in message.content
    assert "[REDACTED:iban]" in message.content


def test_block_on_critical_pii(middleware):
    with pytest.raises(AgentGuardViolation):
        middleware.before_model(
            {"messages": [HumanMessage(content=PII_CARD_TEXT)]},
            runtime=None,
        )


def test_block_emits_block_events(middleware):
    with pytest.raises(AgentGuardViolation):
        middleware.after_model(
            {"messages": [AIMessage(content=PROMPT_INJECTION_TEXT)]},
            runtime=None,
        )

    block_events = [e for e in middleware.guard.events if e.action == Action.BLOCK]
    assert block_events
    assert {e.key for e in block_events} == {"model_output"}


# --- raise_on_violation = False ------------------------------------


def test_block_returns_blocked_result(guard):
    middleware = AgentGuardMiddleware(guard, raise_on_violation=False)

    result = middleware.before_model(
        {"messages": [HumanMessage(content=PROMPT_INJECTION_TEXT)]},
        runtime=None,
    )

    assert result is None
    assert middleware.violation_count == 1


def test_quarantine_returns_blocked_result(quarantine_guard):
    quarantine_handler = MagicMock()
    middleware = AgentGuardMiddleware(
        quarantine_guard,
        quarantine_handler=quarantine_handler,
        raise_on_violation=False,
    )

    result = middleware.before_model(
        {"messages": [HumanMessage(content=PROMPT_INJECTION_TEXT)]},
        runtime=None,
    )

    assert result is None
    quarantine_handler.assert_called_once()
    assert middleware.violation_count == 1


# --- quarantine ----------------------------------------------------


def test_quarantine_handler_called_on_quarantine(quarantine_guard):
    calls = []

    def handler(*, source, content, decision):
        calls.append({"source": source, "decision": decision})

    middleware = AgentGuardMiddleware(quarantine_guard, quarantine_handler=handler)

    result = middleware.before_model(
        {"messages": [HumanMessage(content=PROMPT_INJECTION_TEXT)]},
        runtime=None,
    )

    assert result is None
    assert len(calls) == 1
    assert calls[0]["source"] == "model_input"
    assert calls[0]["decision"].action == Action.QUARANTINE
    assert middleware.violation_count == 1


def test_quarantine_without_handler_still_blocks(quarantine_guard):
    middleware = AgentGuardMiddleware(quarantine_guard)

    with pytest.raises(AgentGuardViolation, match="quarantined"):
        middleware.after_model(
            {"messages": [AIMessage(content=PROMPT_INJECTION_TEXT)]},
            runtime=None,
        )


# --- callbacks ------------------------------------------------------


def test_on_violation_callback_receives_context(guard):
    calls = []

    def on_violation(*, source, decision, content):
        calls.append({"source": source, "content": content})

    middleware = AgentGuardMiddleware(guard, on_violation=on_violation)

    with pytest.raises(AgentGuardViolation):
        middleware.before_model(
            {"messages": [HumanMessage(content=PROMPT_INJECTION_TEXT)]},
            runtime=None,
        )

    assert len(calls) == 1
    assert calls[0]["source"] == "model_input"
    assert calls[0]["content"] == PROMPT_INJECTION_TEXT


def test_on_warn_callback_receives_context(guard):
    calls = []

    def on_warn(*, source, decision, content):
        calls.append({"source": source, "content": content})

    middleware = AgentGuardMiddleware(guard, on_warn=on_warn)

    middleware.before_model(
        {"messages": [HumanMessage(content=PII_EMAIL_TEXT)]},
        runtime=None,
    )

    assert len(calls) == 1
    assert calls[0]["source"] == "model_input"


def test_crashing_on_violation_does_not_bypass_block(guard):
    def crasher(**kwargs):
        raise RuntimeError("callback exploded")

    middleware = AgentGuardMiddleware(guard, on_violation=crasher)

    with pytest.raises(AgentGuardViolation):
        middleware.before_model(
            {"messages": [HumanMessage(content=PROMPT_INJECTION_TEXT)]},
            runtime=None,
        )

    assert middleware.violation_count == 1
