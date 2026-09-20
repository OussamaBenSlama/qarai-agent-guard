from __future__ import annotations

import pytest
from langchain_core.messages import AIMessage, HumanMessage
from qarai_agent_guard import AgentGuardViolation

from qarai_agent_guard_langchain.middleware import AgentGuardMiddleware

from .conftest import PROMPT_INJECTION_TEXT, run


def _create_agent(langchain_agents, fake_chat, responses, guard):
    create_agent = getattr(langchain_agents, "create_agent", None)
    if create_agent is None:
        pytest.skip("create_agent is not available in the installed langchain version")

    FakeListChatModel = fake_chat.FakeListChatModel
    fake_model = FakeListChatModel(responses=responses)

    return create_agent(
        model=fake_model,
        tools=[],
        middleware=[AgentGuardMiddleware(guard)],
    )


def test_full_agent_execution_with_real_guard(guard):
    langchain_agents = pytest.importorskip("langchain.agents")
    fake_chat = pytest.importorskip("langchain_core.language_models.fake_chat_models")

    agent = _create_agent(
        langchain_agents,
        fake_chat,
        responses=["Hello! How can I help you today?"],
        guard=guard,
    )

    response = agent.invoke({"messages": [HumanMessage(content="hello")]})

    assert response
    assert "messages" in response


def test_agent_chain_executes_with_clean_output(guard):
    langchain_agents = pytest.importorskip("langchain.agents")
    fake_chat = pytest.importorskip("langchain_core.language_models.fake_chat_models")

    agent = _create_agent(
        langchain_agents,
        fake_chat,
        responses=["Sure, the capital of France is Paris."],
        guard=guard,
    )

    response = agent.invoke(
        {"messages": [HumanMessage(content="What is the capital of France?")]}
    )

    assert response
    assert any(
        isinstance(m, AIMessage) and "Paris" in m.content for m in response["messages"]
    )


def test_agent_blocked_on_attack_input(guard):
    langchain_agents = pytest.importorskip("langchain.agents")
    fake_chat = pytest.importorskip("langchain_core.language_models.fake_chat_models")

    agent = _create_agent(
        langchain_agents,
        fake_chat,
        responses=["ok"],
        guard=guard,
    )

    with pytest.raises(AgentGuardViolation):
        run(agent.ainvoke({"messages": [HumanMessage(content=PROMPT_INJECTION_TEXT)]}))
