"""Central logger for qarai-agent-guard.

All internal modules share this logger so that log output is formatted
and controlled from a single, consistent place.
"""

from __future__ import annotations

import logging

LOGGER_NAME = "qarai_agent_guard"
_DEFAULT_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"

logger = logging.getLogger(LOGGER_NAME)


def configure_logging(
    level: int = logging.INFO,
    *,
    format_string: str = _DEFAULT_LOG_FORMAT,
    handler: logging.Handler | None = None,
) -> None:
    """Configure the central logger with a formatter and handler.

    Defaults to a console handler at ``INFO`` level when no handler is given.
    """
    if handler is None:
        handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(format_string))
    logger.setLevel(level)
    logger.handlers[:] = [handler]
    logger.propagate = False
