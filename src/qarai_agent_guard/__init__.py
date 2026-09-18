"""qarai-agent-guard: secure AI systems toolkit.

The package exposes its foundation API at the top level:

    from qarai_agent_guard import AgentGuard, Detector, SeverityPolicy

Import schemas, exceptions, and helpers from the core sub-packages:

    from qarai_agent_guard.core.schemas import Action, DetectionResult
    from qarai_agent_guard.core.exceptions import ConfigurationError
    from qarai_agent_guard.core.helpers import parse_severity
"""

from qarai_agent_guard.core.detectors import Detector
from qarai_agent_guard.core.exceptions import AgentGuardViolation
from qarai_agent_guard.core.guards import AgentGuard
from qarai_agent_guard.core.loaders import PolicyLoader
from qarai_agent_guard.core.policies import (
    Policy,
    PolicyExecutor,
    SeverityPolicy,
    default_policy,
    permissive_policy,
    strict_policy,
)
from qarai_agent_guard.core.schemas import SeverityRule

__all__ = [
    "AgentGuard",
    "AgentGuardViolation",
    "Detector",
    "Policy",
    "PolicyExecutor",
    "PolicyLoader",
    "SeverityPolicy",
    "SeverityRule",
    "default_policy",
    "permissive_policy",
    "strict_policy",
]
