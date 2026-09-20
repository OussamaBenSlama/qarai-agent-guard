from __future__ import annotations

from unittest.mock import MagicMock

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from qarai_agent_guard_langchain.middleware import AgentGuardMiddleware

from .conftest import (
    CLEAN_TEXT,
    PII_IBAN_TEXT,
    PROMPT_INJECTION_TEXT,
    make_tool_request,
    run,
)


def test_scan_input_false_skips_blocking_input(guard):
    middleware = AgentGuardMiddleware(guard, scan_input=False)

    result = middleware.before_model(
        {"messages": [HumanMessage(content=PROMPT_INJECTION_TEXT)]},
        runtime=None,
    )

    assert result is None
    assert middleware.violation_count == 0


def test_scan_output_false_skips_redacting_output(guard):
    middleware = AgentGuardMiddleware(guard, scan_output=False)

    result = middleware.after_model(
        {"messages": [AIMessage(content=f"here is {PII_IBAN_TEXT} for you")]},
        runtime=None,
    )

    assert result is None


def test_scan_tool_calls_false_lets_arguments_through(guard):
    middleware = AgentGuardMiddleware(guard, scan_tool_calls=False)

    request = make_tool_request(name="shell", args={"cmd": PROMPT_INJECTION_TEXT})
    handler_result = ToolMessage(content="done", tool_call_id="call-3")
    handler = MagicMock(return_value=handler_result)

    result = middleware.wrap_tool_call(request, handler)

    handler.assert_called_once()
    assert result.content == "done"


def test_scan_tool_results_false_lets_output_through(guard):
    middleware = AgentGuardMiddleware(guard, scan_tool_results=False)

    request = make_tool_request(name="fetch", args={"url": "http://example.com"})
    handler_result = ToolMessage(
        content=f"response contains {PII_IBAN_TEXT} leaked", tool_call_id="call-4"
    )
    handler = MagicMock(return_value=handler_result)

    result = middleware.wrap_tool_call(request, handler)

    assert result is handler_result
    assert "GB29NWBK60161331926819" in result.content


def test_async_variant_honours_scan_tool_calls_false(guard):
    async def handler(_request):
        return ToolMessage(content="done", tool_call_id="call-7")

    middleware = AgentGuardMiddleware(
        guard, scan_tool_calls=False, scan_tool_results=False
    )
    request = make_tool_request(name="shell", args={"cmd": PROMPT_INJECTION_TEXT})

    result = run(middleware.awrap_tool_call(request, handler))

    assert result.content == "done"


def test_clean_input_still_scanned_when_scan_output_is_off(guard):
    middleware = AgentGuardMiddleware(guard, scan_output=False)

    result = middleware.after_model(
        {"messages": [AIMessage(content=CLEAN_TEXT)]},
        runtime=None,
    )

    assert result is None


def test_scan_input_false_does_not_redact_input(guard):
    middleware = AgentGuardMiddleware(guard, scan_input=False)

    message = HumanMessage(content=PII_IBAN_TEXT)
    result = middleware.before_model({"messages": [message]}, runtime=None)

    assert result is None
    assert "GB29NWBK60161331926819" in message.content


def test_scan_output_true_redacts_async_output(guard):
    middleware = AgentGuardMiddleware(guard)

    result = run(
        middleware.aafter_model(
            {"messages": [AIMessage(content=f"here is {PII_IBAN_TEXT}")]},
            runtime=None,
        )
    )

    assert result is not None
    assert "GB29NWBK60161331926819" not in result["messages"][0].content
