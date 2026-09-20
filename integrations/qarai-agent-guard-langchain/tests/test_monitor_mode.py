from __future__ import annotations

from langchain_core.messages import AIMessage, HumanMessage
from qarai_agent_guard.core.schemas import Action

from qarai_agent_guard_langchain.middleware import AgentGuardMiddleware

from .conftest import (
    PROMPT_INJECTION_TEXT,
    make_tool_message_handler,
    make_tool_request,
    monitor_guard,
)


def test_middleware_never_raises_in_monitor_mode(guard):
    guard = monitor_guard(guard)
    middleware = AgentGuardMiddleware(guard)

    result = middleware.before_model(
        {"messages": [HumanMessage(content=PROMPT_INJECTION_TEXT)]},
        runtime=None,
    )

    assert result is None
    assert middleware.violation_count == 0

    detection_events = [e for e in guard.events if e.detector == "prompt_injection"]
    assert detection_events
    assert all(e.action == Action.ALLOW for e in detection_events)


def test_after_model_does_not_raise_in_monitor_mode(guard):
    guard = monitor_guard(guard)
    middleware = AgentGuardMiddleware(guard)

    result = middleware.after_model(
        {"messages": [AIMessage(content=PROMPT_INJECTION_TEXT)]},
        runtime=None,
    )

    assert result is None
    assert middleware.violation_count == 0


def test_tool_call_does_not_raise_in_monitor_mode(guard):
    guard = monitor_guard(guard)
    middleware = AgentGuardMiddleware(guard)

    request = make_tool_request(name="shell", args={"cmd": PROMPT_INJECTION_TEXT})
    handler = make_tool_message_handler("done", call_id="call-m")

    result = middleware.wrap_tool_call(request, handler)

    assert result.content == "done"


def test_tool_result_with_secrets_does_not_raise_in_monitor_mode(guard):
    guard = monitor_guard(guard)
    middleware = AgentGuardMiddleware(guard)

    request = make_tool_request(name="fetch", args={"url": "http://example.com"})
    handler = make_tool_message_handler(
        "secret AKIAIOSFODNN7EXAMPLE", call_id="call-m2"
    )

    result = middleware.wrap_tool_call(request, handler)

    assert result.content == "secret AKIAIOSFODNN7EXAMPLE"
