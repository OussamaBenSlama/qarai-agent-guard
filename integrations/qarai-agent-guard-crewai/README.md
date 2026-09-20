<div align="center">

# qarai-agent-guard-crewai

**CrewAI integration for qarai-agent-guard. Runtime security for AI agents through threat detection, policy enforcement, and content protection.**

[![PyPI version](https://img.shields.io/pypi/v/qarai-agent-guard-crewai.svg?color=blue)](https://pypi.org/project/qarai-agent-guard-crewai/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](../LICENSE)

</div>

---

`qarai-agent-guard-crewai` registers Agent Guard against the CrewAI hook system.
It inspects LLM inputs, LLM outputs, tool arguments, and tool results at fixed interception points.
It does not change your agent or task definitions.

## Installation

```bash
pip install qarai-agent-guard qarai-agent-guard-crewai
```

## Quick start

```python
from qarai_agent_guard import (
    AgentGuard,
    Detector,
    default_policy,
)
from qarai_agent_guard_crewai import enable_guard

guard = AgentGuard(
    detectors=[Detector(name="prompt_injection", default_rules="prompt_injection")],
    policy=default_policy(),
)

enable_guard(guard)
```

By default, `enable_guard()` registers all four hooks:
`before_llm_call`, `after_llm_call`, `before_tool_call`, and `after_tool_call`.

## Documentation

The full documentation has moved to the docs folder. See the
[CrewAI Integration guide](../../docs/crewai.md) for hooks, parameters,
callbacks, and a full workflow example.
