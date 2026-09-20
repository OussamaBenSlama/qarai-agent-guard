from __future__ import annotations

import pytest
from qarai_agent_guard import AgentGuardViolation

from qarai_agent_guard_crewai.global_hooks import enable_guard

from .conftest import (
    CLEAN_TEXT,
    PII_TEXT,
    PROMPT_INJECTION_TEXT,
    SECRET_TEXT,
    fire_after_tool,
    make_tool_context,
)

# --- after_tool_call hook -----------------------------------------


def test_after_tool_clean_result_passes(guard):
    enable_guard(guard)
    ctx = make_tool_context(tool_result=CLEAN_TEXT)
    fire_after_tool(ctx)


def test_after_tool_secrets_in_result_blocks(guard):
    enable_guard(guard)
    ctx = make_tool_context(tool_result=SECRET_TEXT)
    with pytest.raises(AgentGuardViolation):
        fire_after_tool(ctx)


def test_after_tool_pii_in_result_redacts(guard):
    enable_guard(guard)
    ctx = make_tool_context(tool_result=PII_TEXT)
    fire_after_tool(ctx)
    assert "GB29NWBK60161331926819" not in ctx.tool_result


def test_after_tool_none_result_is_noop(guard):
    enable_guard(guard)
    ctx = make_tool_context(tool_result=None)
    fire_after_tool(ctx)


def test_after_tool_uses_tool_name_in_source(guard):
    sources = []

    def on_violation(*, source, decision, content):
        sources.append(source)

    enable_guard(
        guard,
        on_violation=on_violation,
        hooks=["after_tool_call"],
    )
    ctx = make_tool_context(tool_name="fetch", tool_result=SECRET_TEXT)
    with pytest.raises(AgentGuardViolation):
        fire_after_tool(ctx)

    assert sources == ["crewai.after_tool_call:fetch"]


# --- quarantine (via after_tool_call) -----------------------------


def test_quarantine_handler_called_via_after_tool(quarantine_guard):
    quarantined_items = []

    def qhandler(*, source, content, decision):
        quarantined_items.append(content)

    enable_guard(
        quarantine_guard,
        quarantine_handler=qhandler,
        hooks=["after_tool_call"],
    )
    ctx = make_tool_context(tool_result=PROMPT_INJECTION_TEXT)
    fire_after_tool(ctx)

    assert len(quarantined_items) == 1
