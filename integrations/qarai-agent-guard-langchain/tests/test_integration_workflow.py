from __future__ import annotations

import pytest
from langchain_core.messages import AIMessage, HumanMessage
from qarai_agent_guard import AgentGuardViolation, Detector

from qarai_agent_guard_langchain.middleware import AgentGuardMiddleware

from .conftest import (
    CLEAN_TEXT,
    PROMPT_INJECTION_TEXT,
    mixed_guard,
)

pytestmark = pytest.mark.integration


def test_mixed_detector_blocks_injection_through_before_model(injection_engine):
    """The regex branch of a mixed detector blocks during input scanning."""
    middleware = AgentGuardMiddleware(mixed_guard(injection_engine))

    with pytest.raises(AgentGuardViolation):
        middleware.before_model(
            {"messages": [HumanMessage(content=PROMPT_INJECTION_TEXT)]},
            runtime=None,
        )

    assert middleware.violation_count == 1


def test_mixed_detector_allows_clean_input(injection_engine):
    """Benign input passes the mixed detector untouched."""
    middleware = AgentGuardMiddleware(mixed_guard(injection_engine))

    result = middleware.before_model(
        {"messages": [HumanMessage(content=CLEAN_TEXT)]},
        runtime=None,
    )

    assert result is None
    assert middleware.violation_count == 0


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


def test_full_workflow_through_agent_with_model_detector(injection_engine):
    """The full agent workflow runs with a mixed regex+model detector."""
    langchain_agents = pytest.importorskip("langchain.agents")
    create_agent = getattr(langchain_agents, "create_agent", None)
    fake_chat_models = pytest.importorskip(
        "langchain_core.language_models.fake_chat_models"
    )
    FakeListChatModel = fake_chat_models.FakeListChatModel

    fake_model = FakeListChatModel(responses=["The capital of France is Paris."])
    agent = create_agent(
        model=fake_model,
        tools=[],
        middleware=[AgentGuardMiddleware(mixed_guard(injection_engine))],
    )

    response = agent.invoke({"messages": [HumanMessage(content=CLEAN_TEXT)]})

    assert response
    assert any(
        isinstance(m, AIMessage) and "Paris" in m.content for m in response["messages"]
    )
