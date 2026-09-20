class AgentGuardMiddlewareError(Exception):
    """Raised when the middleware itself fails unexpectedly (bug, bad context, etc.)."""
