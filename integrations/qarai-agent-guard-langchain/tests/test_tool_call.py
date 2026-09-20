from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from langchain_core.messages import ToolMessage
from qarai_agent_guard import AgentGuardViolation

from qarai_agent_guard_langchain.middleware import AgentGuardMiddleware

from .conftest import (
    CLEAN_TEXT,
    PII_IBAN_TEXT,
    PROMPT_INJECTION_TEXT,
    make_tool_request,
    run,
)


def test_tool_arguments_blocked_before_handler_runs(guard):
    middleware = AgentGuardMiddleware(guard)
    request = make_tool_request(name="shell", args={"cmd": PROMPT_INJECTION_TEXT})
    handler = MagicMock()

    with pytest.raises(AgentGuardViolation):
        middleware.wrap_tool_call(request, handler)

    handler.assert_not_called()


def test_tool_output_is_redacted(middleware):
    request = make_tool_request(name="fetch", args={"url": "http://example.com"})
    handler_result = ToolMessage(
        content=f"response contains {PII_IBAN_TEXT} leaked",
        tool_call_id="call-1",
    )
    handler = MagicMock(return_value=handler_result)

    result = middleware.wrap_tool_call(request, handler)

    assert isinstance(result, ToolMessage)
    assert "GB29NWBK60161331926819" not in result.content
    assert result.tool_call_id == "call-1"


def test_async_tool_call_blocked_before_handler_runs(guard):
    middleware = AgentGuardMiddleware(guard)
    request = make_tool_request(name="shell", args={"cmd": PROMPT_INJECTION_TEXT})
    called = {"value": False}

    async def handler(_request):
        called["value"] = True
        return ToolMessage(content="x", tool_call_id="y")

    with pytest.raises(AgentGuardViolation):
        run(middleware.awrap_tool_call(request, handler))

    assert called["value"] is False


def test_async_tool_output_is_redacted(middleware):
    request = make_tool_request(name="fetch", args={"url": "http://example.com"})

    async def handler(_request):
        return ToolMessage(
            content=f"response contains {PII_IBAN_TEXT} leaked",
            tool_call_id="call-2",
        )

    result = run(middleware.awrap_tool_call(request, handler))

    assert isinstance(result, ToolMessage)
    assert "GB29NWBK60161331926819" not in result.content
    assert result.tool_call_id == "call-2"


def test_tool_result_with_injection_blocks(middleware):
    request = make_tool_request(name="fetch", args={"url": "http://example.com"})
    handler_result = ToolMessage(content=PROMPT_INJECTION_TEXT, tool_call_id="call-9")
    handler = MagicMock(return_value=handler_result)

    with pytest.raises(AgentGuardViolation):
        middleware.wrap_tool_call(request, handler)


def test_tool_error_from_handler_propagates(middleware):
    request = make_tool_request(name="fetch", args={"url": "http://example.com"})

    def handler(_request):
        raise RuntimeError("downstream tool failed")

    with pytest.raises(RuntimeError, match="downstream tool failed"):
        middleware.wrap_tool_call(request, handler)


def test_tool_call_with_no_arguments_does_not_crash(middleware):
    request = MagicMock()
    request.tool_call = {"name": "search"}
    handler_result = ToolMessage(content="ok", tool_call_id="call-5")
    handler = MagicMock(return_value=handler_result)

    result = middleware.wrap_tool_call(request, handler)

    handler.assert_called_once()
    assert result.content == "ok"


def test_clean_tool_flow_passes(middleware):
    request = make_tool_request(name="fetch", args={"query": CLEAN_TEXT})
    handler_result = ToolMessage(content="all good", tool_call_id="call-6")
    handler = MagicMock(return_value=handler_result)

    result = middleware.wrap_tool_call(request, handler)

    handler.assert_called_once()
    assert result.tool_call_id == "call-6"


def test_tool_call_source_includes_tool_name(guard):
    sources = []

    def on_violation(*, source, decision, content):
        sources.append(source)

    middleware = AgentGuardMiddleware(guard, on_violation=on_violation)
    request = make_tool_request(name="shell", args={"cmd": PROMPT_INJECTION_TEXT})
    handler = MagicMock()

    with pytest.raises(AgentGuardViolation):
        middleware.wrap_tool_call(request, handler)

    assert "tool_call:shell" in sources


def test_tool_output_source_includes_tool_name(guard):
    sources = []

    def on_violation(*, source, decision, content):
        sources.append(source)

    middleware = AgentGuardMiddleware(guard, on_violation=on_violation)
    request = make_tool_request(name="fetch", args={"url": "http://example.com"})
    handler_result = ToolMessage(content=PROMPT_INJECTION_TEXT, tool_call_id="call-8")
    handler = MagicMock(return_value=handler_result)

    with pytest.raises(AgentGuardViolation):
        middleware.wrap_tool_call(request, handler)

    assert "tool_output:fetch" in sources
