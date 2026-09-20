from __future__ import annotations

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


def test_clean_output_passes_through(middleware):
    result = middleware.after_model(
        {"messages": [AIMessage(content=CLEAN_TEXT)]},
        runtime=None,
    )

    assert result is None


def test_pii_output_is_redacted(middleware):
    result = middleware.after_model(
        {"messages": [AIMessage(content=f"here is {PII_IBAN_TEXT} for you")]},
        runtime=None,
    )

    assert result is not None
    new_message = result["messages"][0]
    assert isinstance(new_message, AIMessage)
    assert "GB29NWBK60161331926819" not in new_message.content
    assert "[REDACTED:iban]" in new_message.content


def test_async_variant_redacts_output(middleware):
    result = run(
        middleware.aafter_model(
            {"messages": [AIMessage(content=f"here is {PII_IBAN_TEXT} for you")]},
            runtime=None,
        )
    )

    assert result is not None
    assert "GB29NWBK60161331926819" not in result["messages"][0].content


def test_prompt_injection_output_blocks(middleware):
    with pytest.raises(AgentGuardViolation):
        middleware.after_model(
            {"messages": [AIMessage(content=PROMPT_INJECTION_TEXT)]},
            runtime=None,
        )


def test_secrets_in_output_block(middleware):
    with pytest.raises(AgentGuardViolation):
        middleware.after_model(
            {"messages": [AIMessage(content=SECRET_TEXT)]},
            runtime=None,
        )


def test_scans_only_the_latest_message(middleware):
    result = middleware.after_model(
        {
            "messages": [
                AIMessage(content="thinking..."),
                HumanMessage(content="ok"),
                AIMessage(content=f"here is {PII_IBAN_TEXT}"),
            ]
        },
        runtime=None,
    )

    assert result is not None
    contents = [m.content for m in result["messages"]]
    assert not any("GB29NWBK60161331926819" in c for c in contents)


def test_empty_messages_list_does_not_crash(middleware):
    result = middleware.after_model({"messages": []}, runtime=None)

    assert result is None


def test_non_ai_message_is_ignored(middleware):
    result = middleware.after_model(
        {"messages": [HumanMessage(content=f"here is {PII_IBAN_TEXT}")]},
        runtime=None,
    )

    assert result is None


def test_non_string_message_content_does_not_crash(middleware):
    result = middleware.after_model(
        {"messages": [AIMessage(content=[{"type": "text", "text": "all good"}])]},
        runtime=None,
    )

    assert result is None
