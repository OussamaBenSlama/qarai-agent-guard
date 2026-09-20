from __future__ import annotations

import pytest
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from qarai_agent_guard import AgentGuardViolation

from qarai_agent_guard_langchain.exceptions import AgentGuardMiddlewareError
from qarai_agent_guard_langchain.middleware import AgentGuardMiddleware

from .conftest import (
    CLEAN_TEXT,
    PROMPT_INJECTION_TEXT,
    make_tool_request,
    run,
)


def _break_guard_check(guard, monkeypatch):
    """Make guard.check raise an unexpected (non-policy) error."""

    def boom(*args, **kwargs):
        raise RuntimeError("detector exploded")

    monkeypatch.setattr(guard, "check", boom)


# --- before_model --------------------------------------------------


def test_fail_open_true_swallows_unexpected_error(guard, monkeypatch):
    _break_guard_check(guard, monkeypatch)
    middleware = AgentGuardMiddleware(guard, fail_open=True)

    result = middleware.before_model(
        {"messages": [HumanMessage(content=CLEAN_TEXT)]},
        runtime=None,
    )

    assert result is None
    assert middleware.violation_count == 0


def test_fail_open_false_raises_middleware_error(guard, monkeypatch):
    _break_guard_check(guard, monkeypatch)
    middleware = AgentGuardMiddleware(guard, fail_open=False)

    with pytest.raises(AgentGuardMiddlewareError, match="before_model"):
        middleware.before_model(
            {"messages": [HumanMessage(content=CLEAN_TEXT)]},
            runtime=None,
        )


def test_async_before_model_raises_middleware_error_when_fail_closed(
    guard, monkeypatch
):
    _break_guard_check(guard, monkeypatch)
    middleware = AgentGuardMiddleware(guard, fail_open=False)

    with pytest.raises(AgentGuardMiddlewareError):
        run(
            middleware.abefore_model(
                {"messages": [HumanMessage(content=CLEAN_TEXT)]},
                runtime=None,
            )
        )


def test_on_error_callback_invoked(guard, monkeypatch):
    _break_guard_check(guard, monkeypatch)
    errors_received = []

    def error_recorder(*, hook, error, context):
        errors_received.append({"hook": hook, "error": error})

    middleware = AgentGuardMiddleware(guard, fail_open=True, on_error=error_recorder)

    middleware.before_model(
        {"messages": [HumanMessage(content=CLEAN_TEXT)]},
        runtime=None,
    )

    assert len(errors_received) == 1
    assert errors_received[0]["hook"] == "before_model"
    assert isinstance(errors_received[0]["error"], RuntimeError)


def test_on_error_callback_receives_context(guard, monkeypatch):
    _break_guard_check(guard, monkeypatch)
    states_received = []
    state = {"messages": [HumanMessage(content=CLEAN_TEXT)]}

    def error_recorder(*, hook, error, context):
        states_received.append(context)

    middleware = AgentGuardMiddleware(guard, on_error=error_recorder)

    middleware.before_model(state, runtime=None)

    assert states_received == [state]


def test_on_error_not_invoked_for_policy_violation(guard):
    errors_received = []

    def error_recorder(*, hook, error, context):
        errors_received.append(error)

    middleware = AgentGuardMiddleware(guard, on_error=error_recorder)

    with pytest.raises(AgentGuardViolation):
        middleware.before_model(
            {"messages": [HumanMessage(content=PROMPT_INJECTION_TEXT)]},
            runtime=None,
        )

    assert errors_received == []


def test_policy_violation_raises_regardless_of_fail_open(guard):
    middleware = AgentGuardMiddleware(guard, fail_open=True)

    with pytest.raises(AgentGuardViolation):
        middleware.before_model(
            {"messages": [HumanMessage(content=PROMPT_INJECTION_TEXT)]},
            runtime=None,
        )


def test_policy_violation_not_wrapped_when_fail_closed(guard):
    middleware = AgentGuardMiddleware(guard, fail_open=False)

    with pytest.raises(AgentGuardViolation):
        middleware.before_model(
            {"messages": [HumanMessage(content=PROMPT_INJECTION_TEXT)]},
            runtime=None,
        )


def test_broken_on_error_callback_does_not_bypass_fail_closed(guard, monkeypatch):
    _break_guard_check(guard, monkeypatch)

    def broken_callback(**kwargs):
        raise RuntimeError("callback exploded")

    middleware = AgentGuardMiddleware(guard, fail_open=False, on_error=broken_callback)

    with pytest.raises(AgentGuardMiddlewareError):
        middleware.before_model(
            {"messages": [HumanMessage(content=CLEAN_TEXT)]},
            runtime=None,
        )


# --- after_model ---------------------------------------------------


def test_fail_open_true_swallows_after_model_error(guard, monkeypatch):
    _break_guard_check(guard, monkeypatch)
    middleware = AgentGuardMiddleware(guard, fail_open=True)

    result = middleware.after_model(
        {"messages": [AIMessage(content="generated output")]},
        runtime=None,
    )

    assert result is None


def test_fail_open_false_raises_after_model_error(guard, monkeypatch):
    _break_guard_check(guard, monkeypatch)
    middleware = AgentGuardMiddleware(guard, fail_open=False)

    with pytest.raises(AgentGuardMiddlewareError, match="after_model"):
        middleware.after_model(
            {"messages": [AIMessage(content="generated output")]},
            runtime=None,
        )


def test_async_after_model_raises_when_fail_closed(guard, monkeypatch):
    _break_guard_check(guard, monkeypatch)
    middleware = AgentGuardMiddleware(guard, fail_open=False)

    with pytest.raises(AgentGuardMiddlewareError):
        run(
            middleware.aafter_model(
                {"messages": [AIMessage(content="generated output")]},
                runtime=None,
            )
        )


# --- wrap_tool_call -------------------------------------------------


def test_fail_open_swallows_tool_call_scan_error_and_runs_handler(guard, monkeypatch):
    _break_guard_check(guard, monkeypatch)
    middleware = AgentGuardMiddleware(guard, fail_open=True)

    request = make_tool_request(name="fetch", args={"url": "http://example.com"})
    handler_result = ToolMessage(content="ok", tool_call_id="call-1")
    called = {"value": False}

    def handler(_request):
        called["value"] = True
        return handler_result

    result = middleware.wrap_tool_call(request, handler)

    assert called["value"] is True
    assert result is handler_result


def test_fail_open_false_raises_before_tool_handler_runs(guard, monkeypatch):
    _break_guard_check(guard, monkeypatch)
    middleware = AgentGuardMiddleware(guard, fail_open=False)

    request = make_tool_request(name="shell", args={"cmd": "ls"})
    called = {"value": False}

    def handler(_request):
        called["value"] = True
        return ToolMessage(content="done", tool_call_id="call-2")

    with pytest.raises(AgentGuardMiddlewareError, match="wrap_tool_call"):
        middleware.wrap_tool_call(request, handler)

    assert called["value"] is False


def test_fail_open_swallows_tool_result_scan_error(guard, monkeypatch):
    calls = {"count": 0}

    def boom(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] > 1:
            raise RuntimeError("payload exploded")
        raise RuntimeError("tool_call scan exploded")

    monkeypatch.setattr(guard, "check", boom)
    middleware = AgentGuardMiddleware(guard, fail_open=True)

    request = make_tool_request(name="fetch", args={"url": "http://example.com"})
    handler_result = ToolMessage(content="raw payload", tool_call_id="call-3")
    handler = MagicHandler(return_value=handler_result)

    result = middleware.wrap_tool_call(request, handler)

    assert result is handler_result
    assert calls["count"] >= 2


class MagicHandler:
    def __init__(self, return_value):
        self._return_value = return_value
        self.calls = 0

    def __call__(self, request):
        self.calls += 1
        return self._return_value


def test_async_tool_call_raises_when_fail_closed(guard, monkeypatch):
    _break_guard_check(guard, monkeypatch)
    middleware = AgentGuardMiddleware(guard, fail_open=False)

    request = make_tool_request(name="shell", args={"cmd": "ls"})
    called = {"value": False}

    async def handler(_request):
        called["value"] = True
        return ToolMessage(content="done", tool_call_id="call-4")

    with pytest.raises(AgentGuardMiddlewareError):
        run(middleware.awrap_tool_call(request, handler))

    assert called["value"] is False


def test_async_tool_call_swallows_error_when_fail_open(guard, monkeypatch):
    _break_guard_check(guard, monkeypatch)
    middleware = AgentGuardMiddleware(guard, fail_open=True)

    request = make_tool_request(name="fetch", args={"url": "http://example.com"})

    async def handler(_request):
        return ToolMessage(content="ok", tool_call_id="call-5")

    result = run(middleware.awrap_tool_call(request, handler))

    assert result.content == "ok"
