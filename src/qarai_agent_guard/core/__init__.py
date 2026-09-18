from __future__ import annotations

import importlib as _importlib
from typing import Any as _Any

__all__ = [
    "detectors",
    "exceptions",
    "guards",
    "helpers",
    "loaders",
    "models",
    "policies",
    "schemas",
]

_SUBMODULES: dict[str, str] = {
    "detectors": "qarai_agent_guard.core.detectors",
    "exceptions": "qarai_agent_guard.core.exceptions",
    "guards": "qarai_agent_guard.core.guards",
    "helpers": "qarai_agent_guard.core.helpers",
    "loaders": "qarai_agent_guard.core.loaders",
    "models": "qarai_agent_guard.core.models",
    "policies": "qarai_agent_guard.core.policies",
    "schemas": "qarai_agent_guard.core.schemas",
}


def __getattr__(name: str) -> _Any:
    """Import a lazy sub-package when accessed as an attribute."""
    module_name = _SUBMODULES.get(name)
    if module_name is not None:
        module = _importlib.import_module(module_name)
        globals()[name] = module
        return module
    raise AttributeError(f"module 'qarai_agent_guard.core' has no attribute {name!r}")
