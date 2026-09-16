from typing import Any


class GuardError(Exception):
    """Base exception for agent-guard errors."""


class ConfigurationError(GuardError, ValueError):
    pass


class ModelProviderError(GuardError):
    pass


class ModelLoadError(ModelProviderError):
    pass


class ModelInferenceError(ModelProviderError):
    pass


class ModelOutputError(ModelProviderError):
    pass


class ModelFormatterError(ModelProviderError):
    pass


class DetectorExecutionError(GuardError):
    pass


class PolicyEvaluationError(GuardError):
    pass


class RedactionError(GuardError):
    pass


class AgentGuardViolation(GuardError):
    """Raised when AgentGuard policy enforcement blocks or quarantines content."""

    def __init__(
        self,
        message: str,
        *,
        source: str | None = None,
        decision: Any | None = None,
        content: Any = None,
    ) -> None:
        super().__init__(message)
        self.source = source
        self.decision = decision
        self.content = content
