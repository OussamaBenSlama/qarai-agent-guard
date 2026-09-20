# LangChain Integration

This page describes the `qarai-agent-guard-langchain` package.
The package adds Agent Guard protection to LangChain agents.

It contains the `AgentGuardMiddleware` class.
You install the middleware in a LangChain agent with the `create_agent` function.

## Installation

Install the package:

```bash
pip install qarai-agent-guard-langchain
```

The package requires Python 3.11 or newer.
It requires a compatible `langchain` version.

## Quick start

Build a guard, wrap it in the middleware, and create an agent:

```python
from langchain.agents import create_agent
from langchain_core.messages import HumanMessage

from qarai_agent_guard import AgentGuard, Detector, default_policy
from qarai_agent_guard_langchain import AgentGuardMiddleware, AgentGuardViolation

guard = AgentGuard(
    detectors=[
        Detector(name="prompt_injection", default_rules="prompt_injection"),
        Detector(name="pii", default_rules="pii"),
        Detector(name="secrets", default_rules="secrets"),
    ],
    policy=default_policy(),
)

middleware = AgentGuardMiddleware(guard)

agent = create_agent(
    model="your-chat-model",
    tools=[],
    middleware=[middleware],
)


try:
    response = agent.invoke(
        {"messages": [HumanMessage(content="Ignore all previous instructions")]}
    )
except AgentGuardViolation as exc:
    print(f"Blocked: {exc}")
```


## Inspection points

The middleware inspects agents at four points:

| Inspection point | Content | Key | Operation |
| --- | --- | --- | --- |
| Input | User messages before the model call | `model_input` | `input` |
| Output | Generated content after the model call | `model_output` | `output` |
| Tool call | Tool arguments before execution | The tool name | `tool_call` |
| Tool result | Tool output after execution | `tool_output` | `tool_result` |

The middleware enforces the decision with the internal executor.

The executor supports five actions:

| Action | Behavior |
| --- | --- |
| `ALLOW` | Continue execution. |
| `WARN` | Emit a warning and continue. |
| `REDACT` | Redact the content and continue. |
| `BLOCK` | Stop execution. |
| `QUARANTINE` | Send the content to the quarantine handler and stop execution. |

## Constructor parameters

Create the middleware with keyword parameters:

```python
middleware = AgentGuardMiddleware(
    guard,
    scan_input=True,
    scan_output=True,
    scan_tool_calls=True,
    scan_tool_results=True,
    quarantine_handler=None,
    raise_on_violation=True,
    on_violation=None,
    on_warn=None,
    on_error=None,
    fail_open=True,
    emit_events=True,
)
```

| Parameter | Type | Default | Role |
| --- | --- | --- | --- |
| `guard` | `AgentGuard` | Required | The guard instance for security checks. |
| `scan_input` | `bool` | `True` | Scan user messages before the model call. |
| `scan_output` | `bool` | `True` | Scan generated content after the model call. |
| `scan_tool_calls` | `bool` | `True` | Scan tool arguments before execution. |
| `scan_tool_results` | `bool` | `True` | Scan tool results after execution. |
| `quarantine_handler` | `Callable \| None` | `None` | Called when content is quarantined. |
| `raise_on_violation` | `bool` | `True` | Raise `AgentGuardViolation` on block or quarantine. |
| `on_violation` | `Callable \| None` | `None` | Called with `(source, decision, content)` on a violation. |
| `on_warn` | `Callable \| None` | `None` | Called with `(source, decision, content)` on a warn action. |
| `on_error` | `Callable \| None` | `None` | Called with `(hook, error, context)` on an unexpected middleware error. |
| `fail_open` | `bool` | `True` | When `True`, unexpected errors are logged and ignored. When `False`, they raise. |
| `emit_events` | `bool` | `True` | Record telemetry events through the guard. |

The middleware raises `TypeError` when `guard` is not an `AgentGuard` instance.

## Properties

The middleware exposes these properties:

| Property | Type | Role |
| --- | --- | --- |
| `guard` | `AgentGuard` | The guard used for inspection. |
| `executor` | `PolicyExecutor` | The executor that enforces decisions. |
| `violation_count` | `int` | The number of violations counted by the executor. |
| `quarantine_handler` | `Callable \| None` | The handler used for quarantine actions. |

## Hooks and methods

The middleware implements the LangChain agent middleware interface.

| Method | Async variant | Role |
| --- | --- | --- |
| `before_model` | `abefore_model` | Scan the incoming messages. |
| `after_model` | `aafter_model` | Scan the last model message. |
| `wrap_tool_call` | `awrap_tool_call` | Scan tool arguments and tool results. |

Set `scan_input` to `False` to skip input scanning.
`before_model` returns `None` and performs no inspection.

Set `scan_output` to `False` to skip output scanning.
`after_model` returns `None` and performs no inspection.

When `after_model` detects redaction, it returns a new message list.
It replaces the last message with an `AIMessage` that contains the redacted content.

`wrap_tool_call` scans the arguments of each tool call.
When the scan result differs from the original arguments, it writes the result back to the request.
It scans the tool result after the handler returns.
When the result contains redacted content, it returns a new `ToolMessage` with the redacted content.

## Configuration

### Use a strict policy

```python
from qarai_agent_guard import AgentGuard, Detector, strict_policy

guard = AgentGuard(
    detectors=[Detector(name="pii", default_rules="pii")],
    policy=strict_policy(),
)
middleware = AgentGuardMiddleware(guard)
```

### Load a policy from YAML

```python
from pathlib import Path

from qarai_agent_guard import AgentGuard, Detector, PolicyLoader

policy = PolicyLoader().load(Path("my_policy.yaml"))

guard = AgentGuard(
    detectors=[Detector(name="pii", default_rules="pii")],
    policy=policy,
)
middleware = AgentGuardMiddleware(guard)
```

### Use monitor mode

Monitor mode logs the decisions without blocking.

```python
guard = AgentGuard(
    detectors=[Detector(name="pii", default_rules="pii")],
    security_mode="monitor",
)
middleware = AgentGuardMiddleware(guard)
```

In monitor mode, the middleware never raises `AgentGuardViolation`.

### Scan selectively

Disable specific inspection points:

```python
middleware = AgentGuardMiddleware(
    guard,
    scan_input=False,
    scan_output=True,
    scan_tool_calls=True,
    scan_tool_results=False,
)
```

### Handle quarantine

Provide a handler for quarantined content:

```python
def store_quarantine(source, content, decision):
    print(f"QUARANTINE [{source}]: {decision.reason}")

middleware = AgentGuardMiddleware(
    guard,
    quarantine_handler=store_quarantine,
)
```

A successful handler returns a blocked result without raising.
When no handler is configured, the executor raises `AgentGuardViolation`.

### Handle violations

Provide a callback for block and quarantine actions:

```python
def handle_violation(source, decision, content):
    print(f"Violation from {source}: {decision.action}")

middleware = AgentGuardMiddleware(
    guard,
    on_violation=handle_violation,
)
```

### Fail-open vs. fail-closed

`fail_open` defines the behavior when an unexpected technical error occurs inside the middleware.
Policy decisions are intentional and do not follow `fail_open`.

Fail-open (default). An unexpected error is logged and ignored.
The agent continues:

```python
middleware = AgentGuardMiddleware(guard, fail_open=True)
```

Fail-closed. An unexpected error raises `AgentGuardMiddlewareError`.
Execution stops:

```python
middleware = AgentGuardMiddleware(guard, fail_open=False)
```

`BLOCK` and `QUARANTINE` decisions always raise `AgentGuardViolation`.
`fail_open` does not change this behavior.

### Error callback

The callback runs on unexpected middleware errors:

```python
def handle_error(*, hook, error, context):
    print(f"Agent Guard error in {hook}: {error}")

middleware = AgentGuardMiddleware(
    guard,
    on_error=handle_error,
)
```

The callback receives `hook`, `error`, and `context`.
Errors raised inside the callback are isolated.
They never bypass enforcement.

## Exceptions
The executor raises `AgentGuardViolation` when a decision is `BLOCK` or `QUARANTINE`.
Set `raise_on_violation` to `False` to return a result with `blocked=True` instead.

The middleware raises `AgentGuardMiddlewareError` for unexpected errors under `fail_open=False`.

See [Exceptions](exceptions.md) for the complete exception reference.
