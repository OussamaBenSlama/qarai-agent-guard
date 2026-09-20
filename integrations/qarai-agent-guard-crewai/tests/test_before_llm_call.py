from __future__ import annotations

from types import SimpleNamespace

import pytest
from crewai.hooks import (
    get_after_llm_call_hooks,
    get_after_tool_call_hooks,
    get_before_llm_call_hooks,
    get_before_tool_call_hooks,
)
from qarai_agent_guard import AgentGuardViolation, PolicyExecutor
from qarai_agent_guard.core.schemas import Action

from qarai_agent_guard_crewai.exceptions import AgentGuardHookError
from qarai_agent_guard_crewai.global_hooks import enable_guard

from .conftest import (
    CLEAN_TEXT,
    PII_TEXT,
    PROMPT_INJECTION_TEXT,
    SECRET_TEXT,
    fire_before_llm,
    make_broken_context,
    make_llm_context,
)

# --- registration -------------------------------------------------


def test_registers_all_hooks_by_default(guard):
    enable_guard(guard)
    assert len(get_before_llm_call_hooks()) >= 1
    assert len(get_after_llm_call_hooks()) >= 1
    assert len(get_before_tool_call_hooks()) >= 1
    assert len(get_after_tool_call_hooks()) >= 1


def test_registers_selected_hooks_only(guard):
    enable_guard(guard, hooks=["before_llm_call"])
    assert len(get_before_llm_call_hooks()) >= 1
    assert len(get_after_llm_call_hooks()) == 0
    assert len(get_before_tool_call_hooks()) == 0
    assert len(get_after_tool_call_hooks()) == 0


def test_registers_two_selected_hooks(guard):
    enable_guard(guard, hooks=["before_llm_call", "after_tool_call"])
    assert len(get_before_llm_call_hooks()) >= 1
    assert len(get_after_llm_call_hooks()) == 0
    assert len(get_before_tool_call_hooks()) == 0
    assert len(get_after_tool_call_hooks()) >= 1


def test_rejects_unrecognized_hook(guard):
    with pytest.raises(ValueError, match="Unknown hook name"):
        enable_guard(guard, hooks=["on_model_start"])


def test_rejects_partially_invalid_hooks(guard):
    with pytest.raises(ValueError, match="Unknown hook name"):
        enable_guard(guard, hooks=["before_llm_call", "nonexistent_hook"])


def test_none_guard_raises():
    with pytest.raises(ValueError, match="non-None"):
        enable_guard(None)


def test_returns_policy_executor(guard):
    executor = enable_guard(guard)
    assert isinstance(executor, PolicyExecutor)
    assert executor.guard is guard


# --- before_llm_call hook -----------------------------------------


def test_before_llm_clean_input_passes(guard):
    enable_guard(guard)
    ctx = make_llm_context(messages=[{"role": "user", "content": CLEAN_TEXT}])
    fire_before_llm(ctx)


def test_before_llm_prompt_injection_raises(guard):
    enable_guard(guard)
    ctx = make_llm_context(
        messages=[{"role": "user", "content": PROMPT_INJECTION_TEXT}]
    )
    with pytest.raises(AgentGuardViolation):
        fire_before_llm(ctx)


def test_before_llm_pii_redacts_message_in_place(guard):
    enable_guard(guard)
    msg = {"role": "user", "content": PII_TEXT}
    ctx = make_llm_context(messages=[msg])
    fire_before_llm(ctx)
    assert "GB29NWBK60161331926819" not in msg["content"]


def test_before_llm_secrets_block_message(guard):
    enable_guard(guard)
    ctx = make_llm_context(messages=[{"role": "user", "content": SECRET_TEXT}])
    with pytest.raises(AgentGuardViolation):
        fire_before_llm(ctx)


def test_before_llm_object_message_redacted_in_place(guard):
    enable_guard(guard)
    msg = SimpleNamespace(content=PII_TEXT)
    ctx = make_llm_context(messages=[msg])
    fire_before_llm(ctx)
    assert "GB29NWBK60161331926819" not in msg.content


def test_before_llm_multimodal_list_content_scanned(guard):
    enable_guard(guard)
    ctx = make_llm_context(
        messages=[
            {
                "role": "user",
                "content": [{"type": "text", "text": PROMPT_INJECTION_TEXT}],
            }
        ]
    )
    with pytest.raises(AgentGuardViolation):
        fire_before_llm(ctx)


def test_before_llm_empty_messages_is_noop(guard):
    enable_guard(guard)
    ctx = make_llm_context(messages=[])
    fire_before_llm(ctx)


def test_before_llm_none_content_message_is_skipped(guard):
    enable_guard(guard)
    ctx = make_llm_context(messages=[{"role": "assistant", "content": None}])
    fire_before_llm(ctx)


def test_before_llm_scan_all_messages_true_catches_earlier_injection(guard):
    enable_guard(guard, scan_all_messages=True)
    messages = [
        {"role": "user", "content": PROMPT_INJECTION_TEXT},
        {"role": "assistant", "content": "Sure, here you go."},
        {"role": "user", "content": CLEAN_TEXT},
    ]
    ctx = make_llm_context(messages=messages)
    with pytest.raises(AgentGuardViolation):
        fire_before_llm(ctx)


def test_before_llm_scan_all_messages_false_ignores_earlier_injection(guard):
    enable_guard(guard, scan_all_messages=False)
    messages = [
        {"role": "user", "content": PROMPT_INJECTION_TEXT},
        {"role": "assistant", "content": "Sure, here you go."},
        {"role": "user", "content": CLEAN_TEXT},
    ]
    ctx = make_llm_context(messages=messages)
    fire_before_llm(ctx)


def test_before_llm_scan_all_messages_default_is_false(guard):
    """The default scan_all_messages=False should only scan the last message."""
    enable_guard(guard)
    messages = [
        {"role": "user", "content": PROMPT_INJECTION_TEXT},
        {"role": "user", "content": CLEAN_TEXT},
    ]
    ctx = make_llm_context(messages=messages)
    fire_before_llm(ctx)


def test_before_llm_scan_all_messages_redacts_each_message_in_place(guard):
    enable_guard(guard, scan_all_messages=True)

    msg1 = {"role": "user", "content": PII_TEXT}
    msg2 = {"role": "user", "content": PII_TEXT}
    messages = [msg1, msg2]

    ctx = make_llm_context(messages=messages)

    fire_before_llm(ctx)

    assert "GB29NWBK60161331926819" not in msg1["content"]
    assert "GB29NWBK60161331926819" not in msg2["content"]


def test_before_llm_source_contains_message_index(guard):
    sources = []

    def on_violation(*, source, decision, content):
        sources.append(source)

    enable_guard(
        guard,
        on_violation=on_violation,
        hooks=["before_llm_call"],
    )

    ctx = make_llm_context(
        messages=[
            {"role": "user", "content": CLEAN_TEXT},
            {"role": "user", "content": PROMPT_INJECTION_TEXT},
        ]
    )

    with pytest.raises(AgentGuardViolation):
        fire_before_llm(ctx)

    assert sources == ["crewai.before_llm_call:message_1"]


# --- fail-open / fail-closed (via before_llm_call) ----------------


def test_fail_open_true_swallows_unexpected_error(guard):
    enable_guard(guard, fail_open=True, hooks=["before_llm_call"])
    ctx = make_broken_context()
    fire_before_llm(ctx)


def test_fail_open_false_raises_hook_error(guard):
    enable_guard(guard, fail_open=False, hooks=["before_llm_call"])
    ctx = make_broken_context()
    with pytest.raises(AgentGuardHookError, match="before_llm_call"):
        fire_before_llm(ctx)


def test_on_error_callback_invoked(guard):
    errors_received = []

    def error_recorder(*, hook, error, context=None):
        errors_received.append({"hook": hook, "error": error})

    enable_guard(
        guard,
        fail_open=True,
        on_error=error_recorder,
        hooks=["before_llm_call"],
    )
    ctx = make_broken_context()
    fire_before_llm(ctx)

    assert len(errors_received) == 1
    assert errors_received[0]["hook"] == "before_llm_call"
    assert isinstance(errors_received[0]["error"], Exception)


def test_on_error_receives_context(guard):
    errors_received = []
    ctx = make_broken_context()

    def error_recorder(*, hook, error, context=None):
        errors_received.append(context)

    enable_guard(
        guard,
        fail_open=True,
        on_error=error_recorder,
        hooks=["before_llm_call"],
    )
    fire_before_llm(ctx)

    assert errors_received == [ctx]


def test_on_error_not_invoked_for_policy_violation(guard):
    errors_received = []

    def error_recorder(*, hook, error, context=None):
        errors_received.append(error)

    enable_guard(
        guard,
        on_error=error_recorder,
        hooks=["before_llm_call"],
    )
    ctx = make_llm_context(
        messages=[{"role": "user", "content": PROMPT_INJECTION_TEXT}]
    )
    with pytest.raises(AgentGuardViolation):
        fire_before_llm(ctx)

    assert errors_received == []


def test_policy_violation_always_raises_regardless_of_fail_open(guard):
    """AgentGuardViolation from a real BLOCK is *never* swallowed."""
    enable_guard(guard, fail_open=True)
    ctx = make_llm_context(
        messages=[{"role": "user", "content": PROMPT_INJECTION_TEXT}]
    )
    with pytest.raises(AgentGuardViolation):
        fire_before_llm(ctx)


def test_fail_open_false_policy_violation_still_raises(guard):
    """AgentGuardViolation is raised even when fail_open=False (not wrapped)."""
    enable_guard(guard, fail_open=False)
    ctx = make_llm_context(
        messages=[{"role": "user", "content": PROMPT_INJECTION_TEXT}]
    )
    with pytest.raises(AgentGuardViolation):
        fire_before_llm(ctx)


def test_broken_on_error_callback_does_not_bypass_fail_closed(guard):
    def broken_callback(**kwargs):
        raise RuntimeError("callback exploded")

    enable_guard(
        guard,
        fail_open=False,
        on_error=broken_callback,
        hooks=["before_llm_call"],
    )

    ctx = make_broken_context()

    with pytest.raises(AgentGuardHookError):
        fire_before_llm(ctx)


def test_broken_on_violation_callback_does_not_bypass_block(guard):
    def broken_callback(**kwargs):
        raise RuntimeError("callback exploded")

    enable_guard(
        guard,
        on_violation=broken_callback,
        hooks=["before_llm_call"],
    )

    ctx = make_llm_context(
        messages=[{"role": "user", "content": PROMPT_INJECTION_TEXT}]
    )

    with pytest.raises(AgentGuardViolation):
        fire_before_llm(ctx)


def test_broken_quarantine_handler_does_not_bypass_quarantine(quarantine_guard):
    def broken_handler(**kwargs):
        raise RuntimeError("quarantine handler exploded")

    enable_guard(
        quarantine_guard,
        quarantine_handler=broken_handler,
        hooks=["before_llm_call"],
    )

    ctx = make_llm_context(
        messages=[{"role": "user", "content": PROMPT_INJECTION_TEXT}]
    )

    with pytest.raises(AgentGuardViolation):
        fire_before_llm(ctx)


# --- quarantine (via before_llm_call) -----------------------------


def test_quarantine_handler_called_via_before_llm(quarantine_guard):
    quarantined_items = []

    def qhandler(*, source, content, decision):
        quarantined_items.append(
            {"source": source, "content": content, "action": decision.action}
        )

    executor = enable_guard(
        quarantine_guard,
        quarantine_handler=qhandler,
        hooks=["before_llm_call"],
    )
    ctx = make_llm_context(
        messages=[{"role": "user", "content": PROMPT_INJECTION_TEXT}]
    )
    fire_before_llm(ctx)

    assert len(quarantined_items) == 1
    assert quarantined_items[0]["action"] == Action.QUARANTINE
    assert executor.violations >= 1


# --- on_violation / on_warn (via before_llm_call) -----------------


def test_on_violation_invoked_on_block(guard):
    violations = []

    def violation_recorder(*, source, decision, content):
        violations.append(decision.action)

    enable_guard(guard, on_violation=violation_recorder)
    ctx = make_llm_context(
        messages=[{"role": "user", "content": PROMPT_INJECTION_TEXT}]
    )
    with pytest.raises(AgentGuardViolation):
        fire_before_llm(ctx)

    assert Action.BLOCK in violations


def test_on_warn_invoked_on_warn(guard):
    warnings = []

    def warn_recorder(*, source, decision, content):
        warnings.append({"source": source, "action": decision.action})

    enable_guard(guard, on_warn=warn_recorder)
    ctx = make_llm_context(messages=[{"role": "user", "content": "alice@example.com"}])
    fire_before_llm(ctx)

    assert len(warnings) == 1
    assert warnings[0]["action"] == Action.WARN
