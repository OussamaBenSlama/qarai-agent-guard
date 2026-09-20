# CrewAI Integration

This page describes the `qarai-agent-guard-crewai` package.
The package adds Agent Guard protection to CrewAI crews.

It contains the `enable_guard` function.
The function registers security hooks against the CrewAI hook system.
It does not change your agent or task definitions.

## Installation

Install the packages:

```bash
pip install qarai-agent-guard qarai-agent-guard-crewai
```

The package requires Python 3.11 or newer.
It requires a compatible `crewai` version.
It does not install CrewAI itself.

## Quick start

Build a guard and register it globally:

```python
from qarai_agent_guard import AgentGuard, Detector, default_policy
from qarai_agent_guard_crewai import enable_guard

guard = AgentGuard(
    detectors=[Detector(name="prompt_injection", default_rules="prompt_injection")],
    policy=default_policy(),
)

enable_guard(guard)

# Define your agents, tasks, and crew as usual.
# crew = Crew(agents=[...], tasks=[...])
```

`enable_guard()` registers all four hooks by default.
The guard then evaluates every message and tool interaction in the crew.

## Registered hooks

`enable_guard()` registers these hooks:

| Hook | Content | Key | Operation |
| --- | --- | --- | --- |
| `before_llm_call` | Outgoing messages | `model_input` | `input` |
| `after_llm_call` | Model responses | `model_output` | `output` |
| `before_tool_call` | Tool arguments | `tool_input:<tool name>` | `tool_input` |
| `after_tool_call` | Tool results | `tool_result:<tool name>` | `tool_result` |

The flow of a guarded crew:

```text
User message
     |
     v
before_llm_call
     |
     v
     LLM
     |
     v
after_llm_call
     |
     v
Agent decides to use a tool
     |
     v
before_tool_call
     |
     v
     Tool
     |
     v
after_tool_call
```

At each stage, the guard evaluates the content against the policy.

The executor supports five actions:

| Action | Behavior |
| --- | --- |
| `ALLOW` | Continue execution. |
| `WARN` | Emit a warning and continue. |
| `REDACT` | Redact the content and write the result back to the context. |
| `BLOCK` | Stop execution. |
| `QUARANTINE` | Send the content to the quarantine handler and stop execution. |

## Parameters

Call `enable_guard()` with keyword parameters:

```python
executor = enable_guard(
    guard,
    hooks=None,
    fail_open=True,
    on_error=None,
    on_violation=None,
    on_warn=None,
    quarantine_handler=None,
    raise_on_violation=True,
    emit_events=True,
    scan_all_messages=False,
)
```

| Parameter | Type | Default | Role |
| --- | --- | --- | --- |
| `guard` | `AgentGuard` | Required | The guard instance for security checks. |
| `hooks` | `Iterable[str] \| None` | `None` (all hooks) | The subset of hooks to register. |
| `fail_open` | `bool` | `True` | When `True`, unexpected errors are logged and ignored. When `False`, they raise. |
| `on_error` | `Callable \| None` | `None` | Called with `(hook, error, context)` on unexpected hook errors. |
| `on_violation` | `Callable \| None` | `None` | Called with `(source, decision, content)` on a violation. |
| `on_warn` | `Callable \| None` | `None` | Called with `(source, decision, content)` on a warn action. |
| `quarantine_handler` | `Callable \| None` | `None` | Called with `(source, content, decision)` for quarantine actions. |
| `raise_on_violation` | `bool` | `True` | Raise `AgentGuardViolation` on block or quarantine. |
| `emit_events` | `bool` | `True` | Record telemetry events through the guard. |
| `scan_all_messages` | `bool` | `False` | When `True`, scan the full conversation. When `False`, scan only the latest message. |


The function raises `ValueError` when `guard` is `None`.
It raises `ValueError` when `hooks` contains an unknown hook name.

## Selecting hooks

Register a subset of hooks when you need only partial coverage:

```python
enable_guard(
    guard,
    hooks=[
        "before_llm_call",
        "before_tool_call",
    ],
)
```

Available hook names:

```python
["after_llm_call", "after_tool_call", "before_llm_call", "before_tool_call"]
```

## Fail-open vs. fail-closed

`fail_open` defines the behavior when an unexpected technical error occurs inside a hook.
Policy decisions are intentional and do not follow `fail_open`.

Fail-open (default). An unexpected error is logged and ignored.
The crew continues:

```python
enable_guard(guard, fail_open=True)
```

Fail-closed. An unexpected error raises `AgentGuardHookError`.
Execution stops:

```python
enable_guard(guard, fail_open=False)
```

`BLOCK` and `QUARANTINE` decisions always raise `AgentGuardViolation`.
`fail_open` does not change this behavior.

## Callbacks

### Error callback

The callback runs on unexpected hook errors:

```python
def handle_error(*, hook, error, context):
    print(f"Agent Guard error in {hook}: {error}")

enable_guard(guard, on_error=handle_error)
```

The callback receives `hook`, `error`, and `context`.
Errors raised inside the callback are isolated.
They never bypass enforcement.

### Violation callback

The callback runs when content is blocked or quarantined:

```python
def handle_violation(*, source, decision, content):
    print(f"Violation detected: {source} -> {decision.action}")

enable_guard(guard, on_violation=handle_violation)
```

The callback receives `source`, `decision`, and `content`.
It is informational only.
It does not alter enforcement outcomes.

### Warn callback

The callback runs when the policy returns `WARN`:

```python
def handle_warn(*, source, decision, content):
    print(f"Warning from {source}: {decision.action}")

enable_guard(guard, on_warn=handle_warn)
```

The callback receives `source`, `decision`, and `content`.
It is informational only.
It does not alter enforcement outcomes.

### Quarantine handler

The handler processes quarantined content:

```python
def handle_quarantine(*, source, content, decision):
    print(f"Quarantined content from: {source}")

enable_guard(guard, quarantine_handler=handle_quarantine)
```

The handler receives `source`, `content`, and `decision`.
A successful handler returns a blocked result without raising.
When no handler is configured, the executor raises `AgentGuardViolation`.

## Conversation scanning

By default, the guard inspects only the latest message.
This avoids re-scanning a growing conversation:

```python
enable_guard(guard, scan_all_messages=False)
```

Set `scan_all_messages` to `True` to inspect the entire conversation on every call.
This gives stronger coverage but higher latency:

```python
enable_guard(guard, scan_all_messages=True)
```

## Redaction

When the policy returns `REDACT`, the integration writes the sanitized value back into the relevant CrewAI context:

```text
Before: "My IBAN is GB29NWBK60161331926819"
After:  "My IBAN is [REDACTED:iban]"
```

## Exceptions

The package defines `AgentGuardHookError` for unexpected errors under `fail_open=False`.

```python
from qarai_agent_guard_crewai import AgentGuardViolation, AgentGuardHookError
```

`BLOCK` and `QUARANTINE` decisions raise `AgentGuardViolation`:

```python
from qarai_agent_guard_crewai import AgentGuardViolation

try:
    result = crew.kickoff()
except AgentGuardViolation as exc:
    print(f"Execution blocked: {exc}")
```

Set `raise_on_violation` to `False` to return a result with `blocked=True` instead.

See [Exceptions](exceptions.md) for the complete exception reference.

## Full workflow example

```python
from crewai import Agent, Crew, Task

from qarai_agent_guard import AgentGuard, Detector
from qarai_agent_guard_crewai import enable_guard, AgentGuardViolation

guard = AgentGuard(
    detectors=[
        Detector(name="prompt_injection", default_rules="prompt_injection"),
        Detector(name="pii", default_rules="pii"),
    ],
)

def on_error(*, hook, error, context):
    print(f"[AgentGuard] Unexpected error in {hook}: {error}")

def on_violation(*, source, decision, content):
    print(f"[AgentGuard] Policy violation: {source} -> {decision.action}")

enable_guard(
    guard,
    fail_open=False,
    on_error=on_error,
    on_violation=on_violation,
)

researcher = Agent(
    role="Researcher",
    goal="Research the requested topic",
    backstory="You are a careful research assistant.",
)

task = Task(
    description="Research the requested topic.",
    expected_output="A concise research summary.",
    agent=researcher,
)

crew = Crew(agents=[researcher], tasks=[task])

try:
    result = crew.kickoff()
    print(result)
except AgentGuardViolation as exc:
    print(f"[AgentGuard] Crew execution blocked: {exc}")
```
