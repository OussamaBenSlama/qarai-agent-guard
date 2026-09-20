from __future__ import annotations

import pytest

from qarai_agent_guard import AgentGuard, Detector
from qarai_agent_guard.core.schemas import (
    ExecutionStrategy,
    FailBehavior,
    SecurityMode,
)


def test_detectors_can_be_a_single_detector():
    detector = Detector(default_rules="pii")

    agent_guard = AgentGuard(detectors=detector)

    assert agent_guard.detectors == [detector]


def test_detectors_must_be_detector_instances():
    with pytest.raises(
        TypeError,
        match="detectors must be a Detector or list of Detectors",
    ):
        AgentGuard(detectors=["not-a-detector"])


def test_detectors_can_be_a_list_of_detectors():
    detector1 = Detector(name="pii_detector", default_rules="pii")
    detector2 = Detector(name="secret_detector", default_rules="secrets")

    agent_guard = AgentGuard(detectors=[detector1, detector2])

    assert agent_guard.detectors == [detector1, detector2]


def test_detectors_must_be_detector_or_list():
    with pytest.raises(
        TypeError,
        match="detectors must be a Detector or list of Detectors",
    ):
        AgentGuard(detectors="not-a-detector")


def test_invalid_policy_configuration():
    class NotAPolicy:
        """Missing the required `evaluate` method."""

    with pytest.raises(TypeError, match="policy must implement the Policy interface"):
        AgentGuard(detectors=[], policy=NotAPolicy())


@pytest.mark.parametrize(
    "kwarg",
    ["fail_behavior", "security_mode", "execution_strategy"],
)
def test_invalid_enum_kwarg_raises(kwarg: str):
    with pytest.raises(ValueError, match=kwarg):
        AgentGuard(detectors=[], **{kwarg: "not-a-real-value"})


def test_duplicate_detector_names_raise(pii_detector):
    duplicate = Detector(name="pii", default_rules="pii")
    with pytest.raises(ValueError, match="Duplicate detector name"):
        AgentGuard(detectors=[pii_detector, duplicate])


def test_duplicate_default_detector_name_collision():
    """Two plain Detector() instances share the class-level name by default."""
    with pytest.raises(ValueError, match="Duplicate detector name"):
        AgentGuard(
            detectors=[
                Detector(default_rules="pii"),
                Detector(default_rules="secrets"),
            ]
        )


def test_event_callbacks_must_be_a_list(pii_detector):
    with pytest.raises(TypeError, match="event_callbacks must be list"):
        AgentGuard(detectors=[pii_detector], event_callbacks=lambda e: None)


def test_event_callbacks_must_be_callable(pii_detector):
    with pytest.raises(TypeError, match="event_callbacks\\[0\\] must be callable"):
        AgentGuard(detectors=[pii_detector], event_callbacks=["not-callable"])


@pytest.mark.parametrize(
    "kwarg,enum_cls,enum_member",
    [
        ("fail_behavior", FailBehavior, FailBehavior.FAIL_OPEN),
        ("fail_behavior", FailBehavior, FailBehavior.FAIL_CLOSED),
        ("security_mode", SecurityMode, SecurityMode.ENFORCE),
        ("security_mode", SecurityMode, SecurityMode.MONITOR),
        ("execution_strategy", ExecutionStrategy, ExecutionStrategy.EXHAUSTIVE),
        ("execution_strategy", ExecutionStrategy, ExecutionStrategy.FAIL_FAST),
    ],
)
def test_accepts_enum_member(kwarg, enum_cls, enum_member):
    guard = AgentGuard(detectors=[], **{kwarg: enum_member})
    assert getattr(guard, kwarg) is enum_member


@pytest.mark.parametrize(
    "kwarg,enum_cls,enum_member",
    [
        ("fail_behavior", FailBehavior, FailBehavior.FAIL_OPEN),
        ("fail_behavior", FailBehavior, FailBehavior.FAIL_CLOSED),
        ("security_mode", SecurityMode, SecurityMode.ENFORCE),
        ("security_mode", SecurityMode, SecurityMode.MONITOR),
        ("execution_strategy", ExecutionStrategy, ExecutionStrategy.EXHAUSTIVE),
        ("execution_strategy", ExecutionStrategy, ExecutionStrategy.FAIL_FAST),
    ],
)
def test_accepts_string_value(kwarg, enum_cls, enum_member):
    guard = AgentGuard(detectors=[], **{kwarg: enum_member.value})
    assert getattr(guard, kwarg) is enum_member
