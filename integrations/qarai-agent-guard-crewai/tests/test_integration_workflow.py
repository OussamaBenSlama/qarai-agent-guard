from __future__ import annotations

import pytest
from qarai_agent_guard import AgentGuardViolation, Detector

from qarai_agent_guard_crewai.global_hooks import enable_guard

from .conftest import (
    CLEAN_TEXT,
    PROMPT_INJECTION_TEXT,
    fire_after_llm,
    fire_before_llm,
    make_llm_context,
    mixed_guard,
)

pytestmark = pytest.mark.integration


def test_mixed_detector_blocks_injection_through_before_llm(injection_engine):
    """The regex branch of a mixed detector blocks during input scanning."""
    enable_guard(mixed_guard(injection_engine))

    ctx = make_llm_context(
        messages=[{"role": "user", "content": PROMPT_INJECTION_TEXT}]
    )

    with pytest.raises(AgentGuardViolation):
        fire_before_llm(ctx)


def test_mixed_detector_allows_clean_llm_input(injection_engine):
    """Benign input passes the mixed detector untouched through the hook."""
    executor = enable_guard(mixed_guard(injection_engine))

    ctx = make_llm_context(messages=[{"role": "user", "content": CLEAN_TEXT}])
    fire_before_llm(ctx)

    assert executor.violations == 0


def test_mixed_detector_blocks_injection_through_after_llm(injection_engine):
    """The mixed model detector blocks an attack in the model output."""
    enable_guard(mixed_guard(injection_engine))

    ctx = make_llm_context(response=PROMPT_INJECTION_TEXT)

    with pytest.raises(AgentGuardViolation):
        fire_after_llm(ctx)


def test_regex_and_model_detection_metadata(injection_engine):
    """The mixed detector reports both regex and model evidence."""
    detector = Detector(
        name="mixed_prompt_injection",
        detector_type="mixed",
        default_rules="prompt_injection",
        inference_engine=injection_engine,
        combination_strategy="any",
    )

    result = detector.inspect("user_input", PROMPT_INJECTION_TEXT, operation="write")

    assert result.matched is True
    assert result.metadata["hit_count"] >= 1
    assert result.metadata["model"]["name"] == "deepset/deberta-v3-base-injection"
