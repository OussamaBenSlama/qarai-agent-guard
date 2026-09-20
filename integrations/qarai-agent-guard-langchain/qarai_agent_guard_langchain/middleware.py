from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from langchain.agents.middleware.types import AgentMiddleware
from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    ToolMessage,
)
from langgraph.prebuilt.tool_node import ToolCallRequest
from qarai_agent_guard import AgentGuard, AgentGuardViolation, PolicyExecutor

from qarai_agent_guard_langchain.exceptions import AgentGuardMiddlewareError

logger = logging.getLogger("qarai_agent_guard.langchain")


class AgentGuardMiddleware(AgentMiddleware):
    """LangChain middleware adapter for qarai-agent-guard.

    The middleware does not make security decisions.
    The AgentGuard policy decides the action.
    The PolicyExecutor enforces the action.

    Supported actions:

        ALLOW:
            Continue execution.

        WARN:
            Emit event and continue.

        REDACT:
            Apply redaction and continue.

        BLOCK:
            Stop execution.

        QUARANTINE:
            Send content to quarantine handler and stop execution.

    Unexpected integration errors (not policy decisions) follow ``fail_open``:
    with ``fail_open=True`` (default) they are logged and swallowed so the
    agent keeps running; with ``fail_open=False`` they raise
    ``AgentGuardMiddlewareError``. Policy BLOCK/QUARANTINE decisions always
    raise ``AgentGuardViolation`` and are never swallowed.
    """

    def __init__(
        self,
        guard: AgentGuard,
        *,
        scan_input: bool = True,
        scan_output: bool = True,
        scan_tool_calls: bool = True,
        scan_tool_results: bool = True,
        quarantine_handler: Callable | None = None,
        raise_on_violation: bool = True,
        on_violation: Callable | None = None,
        on_warn: Callable | None = None,
        on_error: Callable | None = None,
        fail_open: bool = True,
        emit_events: bool = True,
    ) -> None:
        if not isinstance(guard, AgentGuard):
            raise TypeError("guard must be an AgentGuard instance")

        self.guard = guard

        self.scan_input = scan_input
        self.scan_output = scan_output
        self.scan_tool_calls = scan_tool_calls
        self.scan_tool_results = scan_tool_results

        self.fail_open = fail_open
        self.on_error = on_error

        self.executor = PolicyExecutor(
            guard=guard,
            quarantine_handler=quarantine_handler,
            raise_on_violation=raise_on_violation,
            on_violation=on_violation,
            on_warn=on_warn,
            emit_events=emit_events,
        )

    @property
    def name(self) -> str:
        return "AgentGuardMiddleware"

    @property
    def violation_count(self) -> int:
        return self.executor.violation_count

    @property
    def quarantine_handler(self) -> Callable | None:
        return self.executor.quarantine_handler

    def _handle_unexpected(
        self,
        entry_point: str,
        error: Exception,
        context: Any,
    ) -> None:
        """Log an unexpected middleware error and apply the fail_open policy.

        Policy violations (``AgentGuardViolation``) never reach this method.
        """
        logger.exception("AgentGuard: unexpected error in %s", entry_point)
        if self.on_error is not None:
            try:
                self.on_error(hook=entry_point, error=error, context=context)
            except Exception:
                logger.exception("AgentGuard: on_error callback raised")
        if not self.fail_open:
            raise AgentGuardMiddlewareError(
                f"AgentGuard middleware {entry_point!r} failed"
            ) from error

    def _extract_content(
        self,
        message: BaseMessage,
    ) -> str:
        if isinstance(message.content, str):
            return message.content

        return str(message.content)

    def before_model(
        self,
        state: Any,
        runtime: Any,
    ) -> dict[str, Any] | None:
        if not self.scan_input:
            return None

        try:
            messages = (
                state.get("messages", [])
                if isinstance(state, dict)
                else getattr(state, "messages", [])
            )

            for message in messages:
                content = self._extract_content(message)

                if not content:
                    continue

                decision, detections = self.guard.check(
                    key="model_input",
                    value=content,
                    operation="input",
                )

                result = self.executor.enforce(
                    decision=decision,
                    content=content,
                    detections=detections,
                    source="model_input",
                )

                if result.content != content:
                    message.content = result.content

            return None

        except AgentGuardViolation:
            raise
        except Exception as exc:
            self._handle_unexpected("before_model", exc, state)
            return None

    async def abefore_model(
        self,
        state,
        runtime,
    ):
        return self.before_model(state, runtime)

    def after_model(
        self,
        state,
        runtime,
    ):
        if not self.scan_output:
            return None

        try:
            messages = (
                state.get("messages", [])
                if isinstance(state, dict)
                else getattr(state, "messages", [])
            )

            if not messages:
                return None

            message = messages[-1]

            if not isinstance(
                message,
                AIMessage,
            ):
                return None

            content = self._extract_content(message)

            decision, detections = self.guard.check(
                key="model_output",
                value=content,
                operation="output",
            )

            result = self.executor.enforce(
                decision=decision,
                content=content,
                detections=detections,
                source="model_output",
            )

            if result.content != content:
                return {"messages": [AIMessage(content=result.content)]}

            return None

        except AgentGuardViolation:
            raise
        except Exception as exc:
            self._handle_unexpected("after_model", exc, state)
            return None

    async def aafter_model(
        self,
        state,
        runtime,
    ):
        return self.after_model(state, runtime)

    def wrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[
            [ToolCallRequest],
            ToolMessage,
        ],
    ) -> ToolMessage:
        tool_name = request.tool_call.get(
            "name",
            "unknown",
        )

        if self.scan_tool_calls:
            try:
                arguments = request.tool_call.get(
                    "args",
                    {},
                )

                decision, detections = self.guard.check(
                    key=tool_name,
                    value=arguments,
                    operation="tool_call",
                )

                result = self.executor.enforce(
                    decision=decision,
                    content=arguments,
                    detections=detections,
                    source=f"tool_call:{tool_name}",
                )

                if result.content != arguments:
                    request.tool_call["args"] = result.content

            except AgentGuardViolation:
                raise
            except Exception as exc:
                self._handle_unexpected("wrap_tool_call", exc, request)

        tool_result = handler(request)

        if not self.scan_tool_results:
            return tool_result

        try:
            content = (
                tool_result.content
                if isinstance(
                    tool_result.content,
                    str,
                )
                else str(tool_result.content)
            )

            decision, detections = self.guard.check(
                key="tool_output",
                value=content,
                operation="tool_result",
            )

            result = self.executor.enforce(
                decision=decision,
                content=content,
                detections=detections,
                source=f"tool_output:{tool_name}",
            )

            if result.content != content:
                return ToolMessage(
                    content=result.content,
                    tool_call_id=tool_result.tool_call_id,
                )

        except AgentGuardViolation:
            raise
        except Exception as exc:
            self._handle_unexpected("wrap_tool_call", exc, tool_result)
            return tool_result

        return tool_result

    async def awrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[
            [ToolCallRequest],
            Awaitable[ToolMessage],
        ],
    ) -> ToolMessage:
        tool_name = request.tool_call.get(
            "name",
            "unknown",
        )

        if self.scan_tool_calls:
            try:
                arguments = request.tool_call.get(
                    "args",
                    {},
                )

                decision, detections = self.guard.check(
                    key=tool_name,
                    value=arguments,
                    operation="tool_call",
                )

                result = self.executor.enforce(
                    decision=decision,
                    content=arguments,
                    detections=detections,
                    source=f"tool_call:{tool_name}",
                )

                if result.content != arguments:
                    request.tool_call["args"] = result.content

            except AgentGuardViolation:
                raise
            except Exception as exc:
                self._handle_unexpected("awrap_tool_call", exc, request)

        tool_result = await handler(request)

        if not self.scan_tool_results:
            return tool_result

        try:
            content = (
                tool_result.content
                if isinstance(
                    tool_result.content,
                    str,
                )
                else str(tool_result.content)
            )

            decision, detections = self.guard.check(
                key="tool_output",
                value=content,
                operation="tool_result",
            )

            result = self.executor.enforce(
                decision=decision,
                content=content,
                detections=detections,
                source=f"tool_output:{tool_name}",
            )

            if result.content != content:
                return ToolMessage(
                    content=result.content,
                    tool_call_id=tool_result.tool_call_id,
                )

        except AgentGuardViolation:
            raise
        except Exception as exc:
            self._handle_unexpected("awrap_tool_call", exc, tool_result)
            return tool_result

        return tool_result
