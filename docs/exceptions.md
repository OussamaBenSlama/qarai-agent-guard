# Exceptions

The library raises typed exceptions.
All exceptions come from `qarai_agent_guard.core.exceptions`.

## Hierarchy

```
GuardError
├── ConfigurationError       (also a ValueError)
├── ModelProviderError
│   ├── ModelLoadError
│   ├── ModelInferenceError
│   ├── ModelOutputError
│   └── ModelFormatterError
├── DetectorExecutionError
├── PolicyEvaluationError
├── RedactionError
└── AgentGuardViolation

ValueError
├── PatternLoaderError
├── PolicyLoaderError
└── StringifyError
```

## GuardError

`GuardError` is the base class for all guard errors.
Catch it to catch every library error:

```python
from qarai_agent_guard.core.exceptions import GuardError

try:
    guard.inspect(key="mem", value=data, operation="write")
except GuardError:
    print("guard error")
```

## ConfigurationError

Raised when configuration is invalid:

- The detector has no rules and no model.
- The detector needs a model but has none.
- `ModelConfig` fields are invalid.

`ConfigurationError` is also a `ValueError`.

```python
from qarai_agent_guard import Detector
from qarai_agent_guard.core.exceptions import ConfigurationError

try:
    Detector(name="empty", detector_type="regex")
except ConfigurationError as exc:
    print(exc)
    # regex detection requires patterns, pattern_paths, or default_rules
```

## ModelProviderError

Raised when a model provider operation fails.

### ModelLoadError

Raised when the model cannot be loaded:

- The model identifier is unknown.
- The provider cannot download the model.

```python
from qarai_agent_guard.core.exceptions import ModelLoadError
```

### ModelInferenceError

Raised when inference fails:

- The provider returns no response.
- The model call raises.

### ModelOutputError

Raised when the model produces invalid output.
The default formatter raises it when the raw output has an unsupported shape:

```python
from qarai_agent_guard.core.exceptions import ModelOutputError
```

### ModelFormatterError

Raised when model input or output formatting fails.
A custom formatter can raise it to reject a value.

## DetectorExecutionError

Raised when a detector raises during inspection.
The guard wraps the original exception in this type.

Failure behavior:

- `fail_open` (default): The guard keeps the error in the `errors` list.
- `fail_closed`: The guard returns a `BLOCK` decision with the error message.

The guard stores errors in the `errors` list that
`inspect_with_results` does not return directly.
Use `run_detectors(errors=...)` to collect them:

```python
from qarai_agent_guard.core.exceptions import DetectorExecutionError

from qarai_agent_guard import AgentGuard, Detector

class CrashingDetector(Detector):
    def __init__(self):
        super().__init__(name="crashing", default_rules="pii")

    def inspect(self, key, value, *, operation):
        raise RuntimeError("boom")

errors = []
guard = AgentGuard(detectors=[CrashingDetector()])
guard.run_detectors(key="mem", value=data, operation="write", errors=errors)

for err in errors:
    print(type(err).__name__, err)
    # DetectorExecutionError Detector 'crashing' failed: boom
```

## PolicyEvaluationError

Raised when the policy `evaluate` method raises.

Failure behavior:

- `fail_open` (default): The guard returns an `ALLOW` decision.
  The decision reason is `Policy evaluation failed: <message>`.
- `fail_closed`: The guard re-raises after emission of a
  `policy_failure` event.

```python
from qarai_agent_guard.core.exceptions import PolicyEvaluationError
```

## RedactionError

Raised when a detector redaction fails and `fail_behavior="fail_closed"`.

The message has this format:
`Detector '<name>' redaction failed: <message>`.

With `fail_open`, the guard returns the content unchanged.

```python
from qarai_agent_guard.core.exceptions import RedactionError
```

## AgentGuardViolation

Raised by `PolicyExecutor` when the guard blocks or quarantines content
and `raise_on_violation=True`.

The message has this format:

```
AgentGuard blocked execution.

Source:
<source>

Reason:
<reason>
```

Use `raise_on_violation=False` to get an `EnforcementResult` instead.

## PatternLoaderError

Raised when a pattern file is invalid or cannot be processed.
This is a `ValueError`, not a `GuardError`.

```python
from qarai_agent_guard.core.exceptions import PatternLoaderError

loader = PatternLoader("unknown/path")

try:
    loader.load_patterns("missing.yaml")
except PatternLoaderError as exc:
    print(exc)
```

## PolicyLoaderError

Raised when a policy file is invalid or cannot be parsed.

```python
from qarai_agent_guard.core.exceptions import PolicyLoaderError
```

## StringifyError

Raised when a value cannot be converted to text safely.
Detection inspects text.
The detector converts the value to text before detection.

`Detector.redact` lets `StringifyError` propagate:

```python
from qarai_agent_guard import Detector
from qarai_agent_guard.core.exceptions import StringifyError

class UnsafeValue:
    def __str__(self):
        raise RuntimeError("no text")

detector = Detector(name="pii", default_rules="pii")

try:
    detector.redact(UnsafeValue())
except StringifyError as exc:
    print(exc)
    # failed to stringify value of type UnsafeValue: no text
```

`Detector.inspect` converts `StringifyError` into a `ValueError`:

```python
try:
    detector.inspect(key="mem", value=UnsafeValue(), operation="write")
except ValueError as exc:
    print(exc)
    # value for 'mem' could not be stringified: failed to stringify value of type UnsafeValue: no text
```

Inside the guard, `inspect` wraps the `ValueError` in
`DetectorExecutionError`. With `fail_open` (default) the guard allows
the operation and keeps the error in the `errors` list.

## Catching by family

```python
from qarai_agent_guard.core.exceptions import (
    GuardError,
    ModelProviderError,
)

try:
    model_detector.inspect(key="mem", value=text, operation="write")
except ModelProviderError as exc:
    print("provider failed:", exc)
except GuardError as exc:
    print("guard failed:", exc)
```

Note: `raise_on_violation=False` produces results, not errors.
Prefer flags when the flow must continue.
