# Policies and Actions

A policy maps detection results to an action.
The guard passes the matched detection results to the policy.
The policy returns a `PolicyDecision` with an action and a reason.


## Severity levels

A rule or a model result has a severity.

| Severity | Meaning |
| --- | --- |
| `info` | Informational. No response needed. |
| `low` | Low risk. |
| `medium` | Medium risk. Redact or warn. |
| `high` | High risk. Block. |
| `critical` | Critical risk. Block. |

The library orders the severities from `info` to `critical`.
The policy evaluates the highest severity in a set of detections.

## Actions

An action is the guard response to a detection.

| Action | Behavior |
| --- | --- |
| `allow` | Allow the operation without intervention. |
| `warn` | Allow the operation and warn. |
| `redact` | Remove or mask sensitive content. |
| `block` | Prevent the operation from proceeding. |
| `quarantine` | Isolate content for further review. |

## The Policy interface

Any object with a callable `evaluate` method is a policy.

The `evaluate` signature:

```python
def evaluate(self, results: list[DetectionResult]) -> PolicyDecision:
    ...
```

It returns a `PolicyDecision`:

| Field | Type | Role |
| --- | --- | --- |
| `action` | `Action` | The action to apply. |
| `reason` | `str` | The reason for the action. |

The guard raises `TypeError` when you pass a policy without a callable `evaluate`.

## Built-in policies

### default_policy

The default policy:

- Blocks critical and high severity.
- Redacts medium severity.
- Warns on low and info severity.

```python
from qarai_agent_guard import AgentGuard, Detector, default_policy

guard = AgentGuard(
    detectors=[Detector(name="pii", default_rules="pii")],
    policy=default_policy(),
)
```

Behavior with a PII detector:

| Payload | Severity | Action |
| --- | --- | --- |
| IBAN `FR1420041010050500013M02606` | `medium` | `REDACT` |
| Card `4111 1111 1111 1111` | `critical` | `BLOCK` |
| Email `jhon.smith@google.com` | `low` | `WARN` |

```python
guard = AgentGuard(detectors=[Detector(name="pii", default_rules="pii")])

print(guard.inspect(key="mem", value="IBAN FR1420041010050500013M02606", operation="write").action)
# Action.REDACT

print(guard.inspect(key="card", value="Card 4111 1111 1111 1111", operation="write").action)
# Action.BLOCK

print(guard.inspect(key="email", value="Mail jhon.smith@google.com", operation="write").action)
# Action.WARN
```

The guard uses `default_policy()` when you do not pass a policy.

### strict_policy

The strict policy:

- Blocks critical, high, and medium severity.
- Warns on low and info severity.

The medium-severity IBAN is blocked:

```python
from qarai_agent_guard import AgentGuard, Detector, strict_policy

guard = AgentGuard(
    detectors=[Detector(name="pii", default_rules="pii")],
    policy=strict_policy(),
)

print(guard.inspect(key="mem", value="IBAN FR1420041010050500013M02606", operation="write").action)
# Action.BLOCK
```

### permissive_policy

The permissive policy:

- Blocks critical severity.
- Warns on high and medium severity.

The medium-severity IBAN is warned:

```python
from qarai_agent_guard import AgentGuard, Detector, permissive_policy

guard = AgentGuard(
    detectors=[Detector(name="pii", default_rules="pii")],
    policy=permissive_policy(),
)

print(guard.inspect(key="mem", value="IBAN FR1420041010050500013M02606", operation="write").action)
# Action.WARN
```

## SeverityRule

A `SeverityRule` maps a set of severities to an action.

```python
from qarai_agent_guard import SeverityRule
from qarai_agent_guard.core.schemas import Action, Severity

rule = SeverityRule(
    severities=(Severity.CRITICAL, Severity.HIGH),
    action=Action.BLOCK,
)
```

| Field | Type | Role |
| --- | --- | --- |
| `severities` | `tuple[Severity, ...]` | The severities covered by the rule. |
| `action` | `Action` | The action for these severities. |

## SeverityPolicy

`SeverityPolicy` maps the highest matched severity to an action.

The policy walks the ordered rules.
When no rule matches the highest severity, it uses the `default_action`.

Construct a policy inline:

```python
from qarai_agent_guard import AgentGuard, Detector, SeverityPolicy, SeverityRule
from qarai_agent_guard.core.schemas import Action, Severity

custom_policy = SeverityPolicy(
    name="inline-strict",
    rules=[
        SeverityRule(
            severities=(Severity.CRITICAL, Severity.HIGH),
            action=Action.BLOCK,
        ),
        SeverityRule(
            severities=(Severity.MEDIUM,),
            action=Action.REDACT,
        ),
        SeverityRule(
            severities=(Severity.LOW, Severity.INFO),
            action=Action.ALLOW,
        ),
    ],
    default_action=Action.ALLOW,
)

guard = AgentGuard(
    detectors=[Detector(name="pii", default_rules="pii")],
    policy=custom_policy,
)
```

Parameters:

| Parameter | Type | Requirement | Role |
| --- | --- | --- | --- |
| `name` | `str` | Required | The policy name. |
| `rules` | `list[SeverityRule]` | Required | The ordered severity rules. |
| `default_action` | `Action` | Optional | The action when no rule matches. Defaults to `Action.ALLOW`. |

Raises:

- `TypeError` if `name` is not a string.
- `ValueError` if `name` is empty.
- `TypeError` if `rules` is not a list.
- `ValueError` if `rules` is empty.
- `TypeError` if `default_action` is not an `Action`.

## Policy decision reason

The policy builds the reason from the detections.
It looks for a result whose highest severity matches the highest severity in the set.
It returns the message of that result.

Example:

```python
decision = guard.inspect(
    key="memory",
    value="Please store IBAN FR1420041010050500013M02606.",
    operation="write",
)

print(decision.reason)
# PII pattern detected in 'memory'
```

When no result has a message, the reason falls back to:

```text
Matched pattern severity: <severity>
```

## Declare a policy in YAML

A policy file has this format:

```yaml
version: "1.0"
name: my-custom-policy
default_action: allow
rules:
  - severities: [critical, high]
    action: block
  - severities: [medium]
    action: redact
  - severities: [low, info]
    action: warn
```

Required fields:

| Field | Type | Role |
| --- | --- | --- |
| `name` | `str` | The policy name. |
| `rules` | `list` | The severity rules. Must not be empty. |
| `default_action` | `str` | The action when no rule matches. Defaults to `"allow"`. |

Each rule requires:

| Field | Type | Role |
| --- | --- | --- |
| `severities` | `list[str]` | The covered severities. |
| `action` | `str` | The action. |

Valid action values: `allow`, `warn`, `redact`, `block`, `quarantine`.

### PolicyLoader

Load a policy file with `PolicyLoader`:

```python
from qarai_agent_guard import PolicyLoader

policy = PolicyLoader().load("my_policy.yaml")
```

`PolicyLoader` returns a `SeverityPolicy`.

Constructor parameter:

| Parameter | Type | Default | Role |
| --- | --- | --- | --- |
| `root` | `str`, `Path`, or `None` | `None` | Base directory for relative policy paths. |

Methods:

| Method | Role |
| --- | --- |
| `validate(data)` | Validates a parsed policy mapping. |
| `load_file(path)` | Loads and validates a policy YAML file. Returns the mapping. |
| `load(path)` | Loads a policy YAML file into a `SeverityPolicy`. |
| `load_default()` | Loads the built-in default policy. |

Raises `PolicyLoaderError` when:

- The top-level value is not a mapping.
- The file has no `name`.
- The file has no `rules` list or the list is empty.
- A rule is not a mapping.
- A rule has no `severities` list.
- A severity is invalid.
- An action is invalid.
- `default_action` is invalid.

Raises `TypeError` when the path is not a string or a `Path`.

### AgentGuard.create with a policy file

`AgentGuard.create` loads the policy file for you:

```python
from qarai_agent_guard import AgentGuard, Detector

guard = AgentGuard.create(
    detectors=[Detector(name="pii", default_rules="pii")],
    policy_path="my_policy.yaml",
)
```

The guard loads the policy when you do not pass an explicit `policy`.

## PolicyExecutor

`PolicyExecutor` applies a policy decision to content.
It turns a decision into side effects.

```python
from qarai_agent_guard import AgentGuard, Detector, PolicyExecutor

guard = AgentGuard(detectors=[Detector(name="pii", default_rules="pii")])
executor = PolicyExecutor(guard=guard)
```

### Parameters

| Parameter | Type | Default | Role |
| --- | --- | --- | --- |
| `guard` | `AgentGuard` or `None` | `None` | Used for redaction and event emission. |
| `quarantine_handler` | `Callable` | `None` | Runs for the `QUARANTINE` action. |
| `on_violation` | `Callable` | `None` | Runs for a policy violation. |
| `on_warn` | `Callable` | `None` | Runs for the `WARN` action. |
| `raise_on_violation` | `bool` | `True` | Raises `AgentGuardViolation` on violations. |
| `emit_events` | `bool` | `True` | Emits telemetry events through the guard. |
| `custom_logger` | `logging.Logger` | Default logger | For internal diagnostics. |

A violation means:

- A `BLOCK` action.
- A `QUARANTINE` action.
- A redaction failure.
- An unrecognized action.

### enforce

`enforce` applies the decision to content:

```python
from qarai_agent_guard.core.schemas import PolicyDecision

result = executor.enforce(
    decision=decision,
    content=content,
    detections=detections,
    source="user_input",
)
```

Parameters:

| Parameter | Type | Default | Role |
| --- | --- | --- | --- |
| `decision` | `PolicyDecision` | Required | The decision to apply. |
| `content` | `Any` | Required | The input, output, or tool payload. |
| `detections` | `list` | `None` | Detection results for redaction. |
| `source` | `str` | `"unknown"` | Identifier of the content source. |

Returns an `EnforcementResult`:

| Field | Type | Role |
| --- | --- | --- |
| `content` | `Any` | The content after enforcement. |
| `action` | `Action` | The applied action. |
| `blocked` | `bool` | Whether the content was blocked. |
| `redacted` | `bool` | Whether the content was redacted. |
| `decision` | `PolicyDecision` or `None` | The source decision. |
| `detections` | `list` or `None` | The detections. |
| `source` | `str` or `None` | The content source. |

### Behavior by action

| Action | Behavior with `raise_on_violation=True` | Behavior with `raise_on_violation=False` |
| --- | --- | --- |
| `ALLOW` | Passes the content through. | Same. |
| `WARN` | Runs `on_warn` and passes the content through. | Same. |
| `REDACT` | Redacts the content with the guard. Raises `AgentGuardViolation` if redaction fails. | Returns `blocked=True` if redaction fails. |
| `BLOCK` | Raises `AgentGuardViolation`. | Returns `blocked=True`. |
| `QUARANTINE` | Runs `quarantine_handler`. Raises `AgentGuardViolation` when there is no handler. | Returns `blocked=True`. |

The executor counts violations in the `violations` property:

```python
from qarai_agent_guard import AgentGuardViolation, PolicyExecutor
from qarai_agent_guard.core.schemas import Action, PolicyDecision

executor = PolicyExecutor(guard=guard, raise_on_violation=False)

try:
    result = executor.enforce(
        decision=PolicyDecision(action=Action.BLOCK, reason="Suspicious input"),
        content="payload",
        source="user_input",
    )
except AgentGuardViolation:
    pass

print(executor.violations)  # 1
```

`violation_count` is an alias for `violations`.

### Callbacks

The callbacks receive the source, the decision, and the content:

```python
def on_violation(source, decision, content):
    print(f"Violation from {source}: {decision.reason}")

executor = PolicyExecutor(
    guard=guard,
    on_violation=on_violation,
    raise_on_violation=False,
)
```

Callback exceptions are logged and swallowed.
`quarantine_handler` exceptions are never swallowed.

Example with BLOCK:

```python
from qarai_agent_guard import AgentGuard, Detector, PolicyExecutor
from qarai_agent_guard.core.schemas import Action, PolicyDecision

guard = AgentGuard(detectors=[Detector(name="pii", default_rules="pii")])
executor = PolicyExecutor(guard=guard, raise_on_violation=False)

result = executor.enforce(
    decision=PolicyDecision(action=Action.BLOCK, reason="Suspicious input"),
    content="payload",
    source="user_input",
)

print(result.blocked)   # True
print(result.action)    # Action.BLOCK
```

Example with REDACT:

```python
guard = AgentGuard(detectors=[Detector(name="pii", default_rules="pii")])

decision = guard.inspect(
    key="memory",
    value="Contact jhon.smith@google.com to schedule the demo.",
    operation="write",
)

_, detections = guard.inspect_with_results(
    key="memory",
    value="Contact jhon.smith@google.com to schedule the demo.",
    operation="write",
)

executor = PolicyExecutor(guard=guard, raise_on_violation=False)
result = executor.enforce(
    decision=decision,
    content="Contact jhon.smith@google.com to schedule the demo.",
    detections=detections,
    source="memory",
)

print(result.redacted)          # True
print(result.content)           # Contact [REDACTED:email] to schedule the demo.
```

Example that raises:

```python
from qarai_agent_guard import AgentGuardViolation, PolicyExecutor
from qarai_agent_guard.core.schemas import Action, PolicyDecision

executor = PolicyExecutor(guard=guard)
try:
    executor.enforce(
        decision=PolicyDecision(action=Action.BLOCK, reason="Suspicious input"),
        content="payload",
        source="user_input",
    )
except AgentGuardViolation as exc:
    print(exc)
    # AgentGuard blocked execution.
    #
    # Source:
    # user_input
    #
    # Reason:
    # Suspicious input
```

### enforce_decision

`enforce_decision` is an alias for `enforce`.

## Custom Policy

Write a custom policy with a class:

```python
from qarai_agent_guard.core.helpers import highest_results_severity
from qarai_agent_guard.core.schemas import Action, PolicyDecision, Severity


class CompanyPolicy:
    def evaluate(self, results):
        severity = highest_results_severity(results)
        if severity in (Severity.CRITICAL, Severity.HIGH):
            return PolicyDecision(action=Action.BLOCK, reason="Blocked by company policy")
        if severity is Severity.MEDIUM:
            return PolicyDecision(action=Action.REDACT, reason="Redacted by company policy")
        return PolicyDecision(action=Action.ALLOW)


guard = AgentGuard(
    detectors=[Detector(name="pii", default_rules="pii")],
    policy=CompanyPolicy(),
)
```

Any object with a callable `evaluate` is accepted.
