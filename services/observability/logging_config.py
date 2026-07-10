"""
Structured JSON logging, shared by the orchestrator and MCP services.

Before this, every service printed its own ad hoc messages via print()
straight to stdout, while services/observability/retry.py already used
the stdlib `logging` module for its retry warnings -- but nothing ever
called logging.basicConfig() or attached a handler/formatter, so those
logger.warning() calls fell back to Python's "handler of last resort"
(unformatted text on stderr). Two code paths, two output streams, two
formats, and no shared way to filter or correlate either of them: an
incident meant grepping raw container stdout for a hunt_id string that
only some lines even contained.

This module gives every service that imports it one shared setup:
  - one JSON object per log line on stdout -- the format most log
    aggregators (Fluent Bit, Promtail/Loki, CloudWatch Logs, ELK/Filebeat)
    expect when scraping container stdout, so fields are queryable
    without a bespoke grok/regex pattern
  - LOG_LEVEL is env-configurable per deploy (default INFO) and actually
    takes effect -- previously nothing set the root logger's level, so
    any logger.info() call anywhere was silently dropped regardless of
    what the message said
  - a hunt_id / hunter_name contextvar that's automatically attached to
    *every* log line emitted while a hunt is in flight -- across
    LangGraph nodes, the MCP client, and the audit writer -- without
    every call site threading hunt_id through an f-string by hand. That
    turns "grep stdout for a hunt ID" into "filter hunt_id=<uuid> in
    your aggregator of choice".

Usage (once, as early as possible in each service's entrypoint):
    from services.observability.logging_config import configure_logging
    configure_logging("thos-orchestrator")

Everywhere else, just use the stdlib pattern:
    import logging
    logger = logging.getLogger(__name__)
    logger.info("hunt started", extra={"hypothesis_id": hypothesis_id})

contextvars.copy_context() is what asyncio.to_thread() uses internally
to hand work to a worker thread, so hunt_id set via set_hunt_context()
is still visible to e.g. audit.py's to_thread-offloaded Postgres writes.
"""
import contextvars
import datetime
import json
import logging
import os
import sys

_hunt_id_var: "contextvars.ContextVar[str | None]" = contextvars.ContextVar("hunt_id", default=None)
_hunter_name_var: "contextvars.ContextVar[str | None]" = contextvars.ContextVar("hunter_name", default=None)

# Attributes every stdlib LogRecord already carries -- used to figure out
# which attributes on a given record were passed in via logging's
# extra={...} (and so should be surfaced as extra structured fields)
# versus internal bookkeeping the formatter already handles explicitly.
_STDLIB_RECORD_FIELDS = set(vars(logging.makeLogRecord({})).keys())


class _ContextFilter(logging.Filter):
    """Injects the hunt_id/hunter_name bound for the current async
    context (if any) into every record that passes through this
    service's handler."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.hunt_id = _hunt_id_var.get()
        record.hunter_name = _hunter_name_var.get()
        return True


class JsonFormatter(logging.Formatter):
    """Renders one LogRecord as one JSON line."""

    def __init__(self, service: str):
        super().__init__()
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "level": record.levelname,
            "service": self.service,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if getattr(record, "hunt_id", None):
            payload["hunt_id"] = record.hunt_id
        if getattr(record, "hunter_name", None):
            payload["hunter_name"] = record.hunter_name

        # Surface anything passed via extra={...} that isn't already
        # handled above, so callers can attach ad hoc structured fields
        # (node name, tool name, siem_type, ...) without this formatter
        # needing to know about them in advance.
        for key, value in vars(record).items():
            if key in _STDLIB_RECORD_FIELDS or key in ("hunt_id", "hunter_name"):
                continue
            try:
                json.dumps(value)
            except TypeError:
                value = str(value)
            payload[key] = value

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


_configured_services: set[str] = set()


def configure_logging(service: str) -> None:
    """Attach one stdout JSON handler to the root logger. Safe to call
    more than once (e.g. from both a module and its __main__ guard) --
    only the first call for a given process takes effect."""
    if _configured_services:
        return
    _configured_services.add(service)

    level_name = os.environ.get("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter(service))
    handler.addFilter(_ContextFilter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)

    # Third-party libraries are noisy at INFO/DEBUG; keep them at WARNING
    # unless the operator explicitly asked for DEBUG everywhere.
    if level > logging.DEBUG:
        for noisy in ("httpx", "httpcore", "chromadb", "gradio", "uvicorn.access"):
            logging.getLogger(noisy).setLevel(logging.WARNING)


def set_hunt_context(hunt_id: str | None, hunter_name: str | None = None):
    """Bind hunt_id/hunter_name onto every log line emitted in this
    async context from here on. Returns an opaque token pair to pass to
    reset_hunt_context() once the hunt completes."""
    return (
        _hunt_id_var.set(hunt_id),
        _hunter_name_var.set(hunter_name),
    )


def reset_hunt_context(tokens) -> None:
    hunt_token, hunter_token = tokens
    _hunt_id_var.reset(hunt_token)
    _hunter_name_var.reset(hunter_token)
