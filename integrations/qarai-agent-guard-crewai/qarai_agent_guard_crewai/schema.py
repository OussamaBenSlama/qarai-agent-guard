from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum


class HookName(StrEnum):
    BEFORE_LLM_CALL = "before_llm_call"
    AFTER_LLM_CALL = "after_llm_call"
    BEFORE_TOOL_CALL = "before_tool_call"
    AFTER_TOOL_CALL = "after_tool_call"


ALL_HOOKS = frozenset(h.value for h in HookName)


@dataclass
class _HookConfig:
    hooks: frozenset[str]
    fail_open: bool
    on_error: Callable[..., None] | None
    scan_all_messages: bool = False
