"""Structured logging configuration for GhostTrace.

Provides JSON-formatted structured logging with request ID context,
timing instrumentation, and configurable log levels. Replaces all
print() calls with proper Python logging.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any

# Context variable for request-scoped request ID
request_id_var: ContextVar[str] = ContextVar("request_id", default="-")


class StructuredFormatter(logging.Formatter):
    """JSON-structured log formatter with request ID and timing context."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": request_id_var.get("-"),
        }

        # Add extra fields if present
        if hasattr(record, "extra_data") and isinstance(record.extra_data, dict):
            log_entry.update(record.extra_data)

        # Add exception info if present
        if record.exc_info and record.exc_info[0] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, default=str)


class ReadableFormatter(logging.Formatter):
    """Human-readable log formatter for local development."""

    COLORS = {
        "DEBUG": "\033[36m",     # cyan
        "INFO": "\033[32m",      # green
        "WARNING": "\033[33m",   # yellow
        "ERROR": "\033[31m",     # red
        "CRITICAL": "\033[1;31m",  # bold red
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, "")
        req_id = request_id_var.get("-")
        timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S")

        parts = [
            f"{color}{timestamp} [{record.levelname:>7}]{self.RESET}",
            f"({record.name})",
            f"[req:{req_id[:8]}]",
            record.getMessage(),
        ]

        if record.exc_info and record.exc_info[0] is not None:
            parts.append(self.formatException(record.exc_info))

        return " ".join(parts)


def setup_logging(level: str = "INFO", format_type: str = "json") -> None:
    """Configure the root logger with structured or readable output.

    Args:
        level: Log level string (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        format_type: "json" for structured JSON logs, "readable" for dev.
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level, logging.INFO))

    # Remove existing handlers to avoid duplicates
    root_logger.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)

    if format_type == "json":
        handler.setFormatter(StructuredFormatter())
    else:
        handler.setFormatter(ReadableFormatter())

    root_logger.addHandler(handler)

    # Quiet down noisy third-party loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("langgraph").setLevel(logging.WARNING)


def log_event(
    logger: logging.Logger,
    level: int,
    message: str,
    **extra: Any,
) -> None:
    """Log a structured event with optional extra fields.

    Args:
        logger: The logger instance to use.
        level: Logging level (logging.INFO, etc.).
        message: The log message.
        **extra: Additional key-value pairs to include in the log entry.
    """
    record = logger.makeRecord(
        name=logger.name,
        level=level,
        fn="",
        lno=0,
        msg=message,
        args=(),
        exc_info=None,
    )
    if extra:
        record.extra_data = extra  # type: ignore[attr-defined]
    logger.handle(record)


def time_it(logger: logging.Logger, operation: str) -> _Timer:
    """Context manager that logs the duration of an operation.

    Usage:
        with time_it(logger, "llm_call"):
            result = await call_llm(...)

    Logs INFO on success with duration in ms, WARNING on failure.
    """
    return _Timer(logger, operation)


class _Timer:
    """Timer context manager for logging operation durations."""

    def __init__(self, logger: logging.Logger, operation: str) -> None:
        self.logger = logger
        self.operation = operation
        self.start_time: float = 0.0

    def __enter__(self) -> _Timer:
        self.start_time = time.perf_counter()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        duration_ms = (time.perf_counter() - self.start_time) * 1000
        extra = {
            "operation": self.operation,
            "duration_ms": round(duration_ms, 2),
        }

        if exc_type is None:
            log_event(
                self.logger,
                logging.INFO,
                f"{self.operation} completed in {duration_ms:.0f}ms",
                **extra,
            )
        else:
            extra["error"] = str(exc_val)
            log_event(
                self.logger,
                logging.WARNING,
                f"{self.operation} failed after {duration_ms:.0f}ms: {exc_val}",
                **extra,
            )
        return False  # Don't suppress exceptions
