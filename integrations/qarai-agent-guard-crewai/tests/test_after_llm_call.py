from __future__ import annotations

from types import SimpleNamespace

import pytest
from qarai_agent_guard import AgentGuardViolation

from qarai_agent_guard_crewai.global_hooks import enable_guard

from .conftest import (
    CLEAN_TEXT,
    PII_TEXT,
    PROMPT_INJECTION_TEXT,
    SECRET_TEXT,
    fire_after_llm,
    fire_before_llm,
    make_llm_context,
)

# --- after_llm_call hook ------------------------------------------


def test_after_llm_clean_response_passes(guard):
    enable_guard(guard)
    ctx = make_llm_context(response=CLEAN_TEXT)
    fire_after_llm(ctx)


def test_after_llm_injection_in_response_blocks(guard):
    enable_guard(guard)
    ctx = make_llm_context(response=PROMPT_INJECTION_TEXT)
    with pytest.raises(AgentGuardViolation):
        fire_after_llm(ctx)


def test_after_llm_pii_in_response_redacts(guard):
    enable_guard(guard)
    ctx = make_llm_context(response=PII_TEXT)
    fire_after_llm(ctx)
    assert "GB29NWBK60161331926819" not in ctx.response


def test_after_llm_none_response_is_noop(guard):
    enable_guard(guard)
    ctx = make_llm_context(response=None)
    fire_after_llm(ctx)


def test_after_llm_secrets_in_response_blocks(guard):
    enable_guard(guard)
    ctx = make_llm_context(response=SECRET_TEXT)
    with pytest.raises(AgentGuardViolation):
        fire_after_llm(ctx)


def test_after_llm_redacted_response_writes_to_object_context(guard):
    enable_guard(guard)
    ctx = SimpleNamespace(response=PII_TEXT)
    fire_after_llm(ctx)
    assert "GB29NWBK60161331926819" not in ctx.response


# --- quarantine (via after_llm_call) ------------------------------


def test_quarantine_handler_called_via_after_llm(quarantine_guard):
    quarantined_items = []

    def qhandler(*, source, content, decision):
        quarantined_items.append(content)

    enable_guard(
        quarantine_guard,
        quarantine_handler=qhandler,
        hooks=["after_llm_call"],
    )
    ctx = make_llm_context(response=PROMPT_INJECTION_TEXT)
    fire_after_llm(ctx)

    assert len(quarantined_items) == 1


# --- executor violation counting ----------------------------------


def test_violations_increment_across_calls(guard):
    executor = enable_guard(guard)

    ctx1 = make_llm_context(
        messages=[{"role": "user", "content": PROMPT_INJECTION_TEXT}]
    )
    with pytest.raises(AgentGuardViolation):
        fire_before_llm(ctx1)

    ctx2 = make_llm_context(response=SECRET_TEXT)
    with pytest.raises(AgentGuardViolation):
        fire_after_llm(ctx2)

    assert executor.violations >= 2


def test_no_violations_for_clean_traffic(guard):
    executor = enable_guard(guard)
    fire_before_llm(
        make_llm_context(messages=[{"role": "user", "content": CLEAN_TEXT}])
    )
    fire_after_llm(make_llm_context(response=CLEAN_TEXT))
    assert executor.violations == 0
