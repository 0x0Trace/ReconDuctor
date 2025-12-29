"""Structured logging using structlog."""

from __future__ import annotations

import logging
import sys
from typing import Any, Optional

import structlog
from structlog.typing import Processor


def setup_logging(
    level: str = "INFO",
    json_format: bool = False,
    log_file: Optional[str] = None,
) -> None:
    """
    Configure structured logging for the application.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        json_format: If True, output logs in JSON format
        log_file: Optional file path for logging output
    """
    # Configure standard library logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, level.upper()),
    )

    # Common processors for all configurations
    # Note: add_logger_name removed as PrintLoggerFactory doesn't support it
    shared_processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    if json_format:
        # JSON format for production/log aggregation
        processors: list[Processor] = shared_processors + [
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ]
    else:
        # Pretty console format for development
        processors = shared_processors + [
            structlog.dev.ConsoleRenderer(
                colors=True,
                exception_formatter=structlog.dev.plain_traceback,
            ),
        ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper())
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # If log file is specified, add file handler
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(getattr(logging, level.upper()))
        logging.getLogger().addHandler(file_handler)


def get_logger(name: Optional[str] = None, **initial_context: Any) -> structlog.BoundLogger:
    """
    Get a bound logger with optional initial context.

    Args:
        name: Logger name (optional)
        **initial_context: Initial context key-value pairs to bind

    Returns:
        A structlog bound logger instance
    """
    logger = structlog.get_logger(name)
    if initial_context:
        logger = logger.bind(**initial_context)
    return logger


class LoggerMixin:
    """Mixin class that provides a logger property."""

    @property
    def logger(self) -> structlog.BoundLogger:
        """Get a logger bound with the class name."""
        return get_logger(self.__class__.__name__)


# Convenience functions for common log patterns
def log_tool_start(tool_name: str, **context: Any) -> None:
    """Log the start of an external tool execution."""
    logger = get_logger("tools")
    logger.info(f"Starting {tool_name}", tool=tool_name, action="start", **context)


def log_tool_complete(
    tool_name: str,
    success: bool,
    duration: float,
    **context: Any,
) -> None:
    """Log the completion of an external tool execution."""
    logger = get_logger("tools")
    level = "info" if success else "error"
    getattr(logger, level)(
        f"{tool_name} {'completed' if success else 'failed'}",
        tool=tool_name,
        action="complete",
        success=success,
        duration_seconds=round(duration, 2),
        **context,
    )


def log_phase_start(phase: int, phase_name: str, **context: Any) -> None:
    """Log the start of a reconnaissance phase."""
    logger = get_logger("phases")
    logger.info(
        f"Starting Phase {phase}: {phase_name}",
        phase=phase,
        phase_name=phase_name,
        action="phase_start",
        **context,
    )


def log_phase_complete(
    phase: int,
    phase_name: str,
    success: bool,
    duration: float,
    **context: Any,
) -> None:
    """Log the completion of a reconnaissance phase."""
    logger = get_logger("phases")
    level = "info" if success else "error"
    getattr(logger, level)(
        f"Phase {phase}: {phase_name} {'completed' if success else 'failed'}",
        phase=phase,
        phase_name=phase_name,
        action="phase_complete",
        success=success,
        duration_seconds=round(duration, 2),
        **context,
    )


def log_finding(
    finding_type: str,
    severity: str,
    target: str,
    **details: Any,
) -> None:
    """Log a security finding."""
    logger = get_logger("findings")
    logger.warning(
        f"[{severity.upper()}] {finding_type} on {target}",
        finding_type=finding_type,
        severity=severity,
        target=target,
        **details,
    )
