from __future__ import annotations

import pytest
from qarai_agent_guard import AgentGuardViolation

from qarai_agent_guard_crewai.global_hooks import enable_guard

from .conftest import (
    CLEAN_TEXT,
    PROMPT_INJECTION_TEXT,
    fire_before_tool,
    make_tool_context,
)

# --- before_tool_call hook ----------------------------------------


def test_before_tool_clean_input_passes(guard):
    enable_guard(guard)
    ctx = make_tool_context(tool_input={"query": CLEAN_TEXT})
    fire_before_tool(ctx)


def test_before_tool_injection_in_tool_input_blocks(guard):
    enable_guard(guard)
    ctx = make_tool_context(tool_input={"query": PROMPT_INJECTION_TEXT})
    with pytest.raises(AgentGuardViolation):
        fire_before_tool(ctx)


def test_before_tool_empty_tool_input_is_noop(guard):
    enable_guard(guard)
    ctx = make_tool_context(tool_input={})
    fire_before_tool(ctx)


def test_before_tool_uses_tool_name_in_source(guard):
    sources = []

    def on_violation(*, source, decision, content):
        sources.append(source)

    enable_guard(
        guard,
        on_violation=on_violation,
        hooks=["before_tool_call"],
    )
    ctx = make_tool_context(
        tool_name="shell",
        tool_input={"cmd": PROMPT_INJECTION_TEXT},
    )
    with pytest.raises(AgentGuardViolation):
        fire_before_tool(ctx)

    assert sources == ["crewai.before_tool_call:shell"]
