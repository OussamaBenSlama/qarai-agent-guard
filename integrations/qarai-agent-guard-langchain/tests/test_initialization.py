from __future__ import annotations

import pytest
from qarai_agent_guard import PolicyExecutor

from qarai_agent_guard_langchain.middleware import AgentGuardMiddleware


def test_rejects_non_agent_guard_instance():
    with pytest.raises(TypeError):
        AgentGuardMiddleware("not-a-guard")


def test_default_flags_are_all_enabled(middleware):
    assert middleware.scan_input is True
    assert middleware.scan_output is True
    assert middleware.scan_tool_calls is True
    assert middleware.scan_tool_results is True
    assert middleware.violation_count == 0


def test_custom_flags_are_stored(guard):
    middleware = AgentGuardMiddleware(
        guard,
        scan_input=False,
        scan_output=False,
        scan_tool_calls=False,
        scan_tool_results=False,
    )

    assert middleware.scan_input is False
    assert middleware.scan_output is False
    assert middleware.scan_tool_calls is False
    assert middleware.scan_tool_results is False


def test_default_fail_open_and_on_error(middleware):
    assert middleware.fail_open is True
    assert middleware.on_error is None


def test_custom_fail_open_and_on_error_are_stored(guard):
    def handler(**kwargs):
        pass

    middleware = AgentGuardMiddleware(guard, fail_open=False, on_error=handler)

    assert middleware.fail_open is False
    assert middleware.on_error is handler


def test_exposes_policy_executor(middleware):
    assert isinstance(middleware.executor, PolicyExecutor)
    assert middleware.executor.guard is middleware.guard


def test_raise_on_violation_false_returns_results(guard):
    middleware = AgentGuardMiddleware(guard, raise_on_violation=False)
    assert middleware.executor.raise_on_violation is False


def test_quarantine_handler_is_forwarded_to_executor(quarantine_guard):
    calls = []

    def handler(*, source, content, decision):
        calls.append(source)

    middleware = AgentGuardMiddleware(quarantine_guard, quarantine_handler=handler)

    assert middleware.quarantine_handler is handler
    assert middleware.executor.quarantine_handler is handler


def test_violation_count_aliases_executor(middleware):
    assert middleware.violation_count == middleware.executor.violation_count
    assert middleware.violation_count == middleware.executor.violations
