from __future__ import annotations

from types import SimpleNamespace

import pytest
from langchain_core.messages import AIMessage, HumanMessage
from qarai_agent_guard import AgentGuardViolation

from .conftest import (
    CLEAN_TEXT,
    PII_IBAN_TEXT,
    PROMPT_INJECTION_TEXT,
    SECRET_TEXT,
    run,
)


def test_clean_input_passes_through(middleware):
    result = middleware.before_model(
        {"messages": [HumanMessage(content=CLEAN_TEXT)]},
        runtime=None,
    )

    assert result is None
    assert middleware.violation_count == 0


def test_prompt_injection_input_raises(middleware):
    with pytest.raises(AgentGuardViolation) as exc_info:
        middleware.before_model(
            {"messages": [HumanMessage(content=PROMPT_INJECTION_TEXT)]},
            runtime=None,
        )

    assert middleware.violation_count == 1
    assert "model_input" in str(exc_info.value)


def test_async_variant_blocks_before_model(middleware):
    with pytest.raises(AgentGuardViolation):
        run(
            middleware.abefore_model(
                {"messages": [HumanMessage(content=PROMPT_INJECTION_TEXT)]},
                runtime=None,
            )
        )

    assert middleware.violation_count == 1


def test_secret_in_input_blocks(middleware):
    with pytest.raises(AgentGuardViolation):
        middleware.before_model(
            {"messages": [HumanMessage(content=SECRET_TEXT)]},
            runtime=None,
        )


def test_scans_all_messages(middleware):
    with pytest.raises(AgentGuardViolation):
        middleware.before_model(
            {
                "messages": [
                    HumanMessage(content="hi there"),
                    AIMessage(content="how can I help?"),
                    HumanMessage(content=PROMPT_INJECTION_TEXT),
                    AIMessage(content="sure, one moment"),
                ]
            },
            runtime=None,
        )

    assert middleware.violation_count == 1


def test_empty_messages_list_does_not_crash(middleware):
    result = middleware.before_model({"messages": []}, runtime=None)

    assert result is None
    assert middleware.violation_count == 0


def test_non_string_message_content_does_not_crash(middleware):
    result = middleware.before_model(
        {"messages": [HumanMessage(content=[{"type": "text", "text": CLEAN_TEXT}])]},
        runtime=None,
    )
    assert result is None


def test_non_string_message_content_with_injection_blocks(middleware):
    with pytest.raises(AgentGuardViolation):
        middleware.before_model(
            {
                "messages": [
                    HumanMessage(
                        content=[{"type": "text", "text": PROMPT_INJECTION_TEXT}]
                    )
                ]
            },
            runtime=None,
        )


def test_pii_input_is_redacted_in_place(middleware):
    message = HumanMessage(content=PII_IBAN_TEXT)
    result = middleware.before_model({"messages": [message]}, runtime=None)

    assert result is None
    assert "GB29NWBK60161331926819" not in message.content
    assert "[REDACTED:" in message.content


def test_state_object_with_messages_attribute_is_scanned(middleware):
    state = SimpleNamespace(messages=[HumanMessage(content=PROMPT_INJECTION_TEXT)])
    with pytest.raises(AgentGuardViolation):
        middleware.before_model(state, runtime=None)


def test_state_without_messages_is_noop(middleware):
    result = middleware.before_model({"not_messages": []}, runtime=None)
    assert result is None
