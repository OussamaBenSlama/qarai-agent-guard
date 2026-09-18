from __future__ import annotations

import importlib as _importlib
from typing import Any as _Any

from qarai_agent_guard.core.policies.base import (
    DefaultPolicy,
    Policy,
    SeverityPolicy,
    severity_rule_from_mapping,
)
from qarai_agent_guard.core.policies.defaults import (
    default_policy,
    permissive_policy,
    strict_policy,
)

__all__ = [
    "DefaultPolicy",
    "Policy",
    "PolicyExecutor",
    "SeverityPolicy",
    "default_policy",
    "permissive_policy",
    "severity_rule_from_mapping",
    "strict_policy",
]


def __getattr__(name: str) -> _Any:
    """Import ``PolicyExecutor`` lazily to avoid a circular import."""
    if name == "PolicyExecutor":
        module = _importlib.import_module("qarai_agent_guard.core.policies.enforcement")
        policy_executor = module.PolicyExecutor
        globals()["PolicyExecutor"] = policy_executor
        return policy_executor
    raise AttributeError(
        f"module 'qarai_agent_guard.core.policies' has no attribute {name!r}"
    )
