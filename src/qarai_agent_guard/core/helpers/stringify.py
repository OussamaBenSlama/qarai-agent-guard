from __future__ import annotations

from typing import Any

from qarai_agent_guard.core.exceptions import StringifyError

DEFAULT_MAX_DEPTH = 50


def _stringify(
    value: Any,
    *,
    _depth: int = 0,
    _max_depth: int = DEFAULT_MAX_DEPTH,
    _seen: set[int] | None = None,
) -> str:
    """Convert arbitrary values into a flat string for pattern matching.

    Convert collections and mappings recursively. The detectors use the
    result to scan structured payloads consistently.

    Args:
        value (Any): Value to convert. Required.
        _max_depth (int): Maximum recursion depth for nested collections
            and mappings. The limit prevents circular references and
            excessively deep or malicious payloads.

    Returns:
        str: The string representation for regex inspection.

    Raises:
        StringifyError: If ``value`` contains a circular reference or
            exceeds ``_max_depth``. The error also occurs when the
            ``__str__`` or ``__repr__`` of an object raises.
    """
    if _seen is None:
        _seen = set()

    if value is None:
        return ""

    if isinstance(value, str):
        return value

    if isinstance(value, list | tuple | set | dict):
        if _depth >= _max_depth:
            raise StringifyError(
                f"maximum nesting depth ({_max_depth}) exceeded "
                "while stringifying value"
            )

        value_id = id(value)

        if value_id in _seen:
            raise StringifyError("circular reference detected while stringifying value")

        _seen = _seen | {value_id}

        if isinstance(value, dict):
            try:

                def stringify_entry(key: Any, item: Any) -> str:
                    stringified_key = _stringify(
                        key,
                        _depth=_depth + 1,
                        _max_depth=_max_depth,
                        _seen=_seen,
                    )
                    stringified_value = _stringify(
                        item,
                        _depth=_depth + 1,
                        _max_depth=_max_depth,
                        _seen=_seen,
                    )
                    return f"{stringified_key}: {stringified_value}"

                return "\n".join(
                    stringify_entry(key, item) for key, item in value.items()
                )
            except StringifyError:
                raise
            except Exception as exc:
                raise StringifyError(f"failed to stringify dict entry: {exc}") from exc

        try:
            return "\n".join(
                _stringify(
                    item,
                    _depth=_depth + 1,
                    _max_depth=_max_depth,
                    _seen=_seen,
                )
                for item in value
            )
        except StringifyError:
            raise
        except Exception as exc:
            raise StringifyError(
                f"failed to stringify collection entry: {exc}"
            ) from exc

    try:
        return str(value)
    except Exception as exc:
        raise StringifyError(
            f"failed to stringify value of type {type(value).__name__}: {exc}"
        ) from exc
