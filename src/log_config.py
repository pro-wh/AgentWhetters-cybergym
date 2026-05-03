"""Logging configuration for the CyberGym purple agent.

Defines a TRACE level (numeric 5, below DEBUG=10) for internal step-by-step
details that are useful for post-run analysis but too noisy for normal operation.

Log levels:
    TRACE (5)   — every internal step: triage scores, compaction, tool output sizes
    DEBUG (10)  — standard Python debug (not used by this codebase)
    INFO (20)   — high-signal events: hypothesis parsed, PoC submitted, feedback class, tokens
    WARNING (30)— recoverable issues: pipeline fallback, budget exhausted
    ERROR (40)  — API failures and unrecoverable errors

Set LOG_LEVEL=TRACE in .env to see full execution trace for analysis.
Set LOG_LEVEL=INFO (default) for clean competition runs.
"""

from __future__ import annotations

import logging

# ---------------------------------------------------------------------------
# TRACE level — below DEBUG, for internal step details
# ---------------------------------------------------------------------------

TRACE = 5
logging.addLevelName(TRACE, "TRACE")


def _trace(self: logging.Logger, message: str, *args, **kwargs) -> None:
    if self.isEnabledFor(TRACE):
        self._log(TRACE, message, args, **kwargs)


logging.Logger.trace = _trace  # type: ignore[attr-defined]


def get_level(name: str) -> int:
    """Resolve a level name (including TRACE) to its numeric value."""
    name = name.upper()
    if name == "TRACE":
        return TRACE
    level = getattr(logging, name, None)
    if isinstance(level, int):
        return level
    return logging.INFO


# ---------------------------------------------------------------------------
# Formatter — includes level name padded for alignment
# ---------------------------------------------------------------------------

class AgentFormatter(logging.Formatter):
    """Compact formatter: LEVEL  [module] message"""

    _FMT = "%(asctime)s %(levelname)-7s [%(name)s] %(message)s"
    _DATE = "%H:%M:%S"

    def __init__(self):
        super().__init__(fmt=self._FMT, datefmt=self._DATE)


def configure(level_name: str = "INFO") -> None:
    """Configure root logging with AgentFormatter and resolved level."""
    level = get_level(level_name)
    handler = logging.StreamHandler()
    handler.setFormatter(AgentFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
    # Quiet noisy third-party loggers unless we're in TRACE mode
    if level > TRACE:
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)
        logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
        logging.getLogger("openai").setLevel(logging.WARNING)
