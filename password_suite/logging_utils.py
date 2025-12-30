from __future__ import annotations

import json
import logging
import logging.handlers
from pathlib import Path
from typing import Any, Dict, Optional


def setup_logger(
    log_path: str | Path = "suite.log",
    level: int = logging.INFO,
    max_bytes: int = 1_000_000,
    backup_count: int = 3,
) -> logging.Logger:
    """Create a rotating-file logger.

    IMPORTANT: This logger is designed to avoid logging plaintext passwords.
    Only log high-level actions and aggregate/metadata.
    """
    logger = logging.getLogger("password_security_suite")
    if logger.handlers:
        return logger  # already configured

    logger.setLevel(level)

    log_path = Path(log_path)
    handler = logging.handlers.RotatingFileHandler(
        log_path, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
    )
    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(message)s", datefmt="%Y-%m-%dT%H:%M:%S%z"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # Also log warnings+ to stderr
    stream = logging.StreamHandler()
    stream.setLevel(logging.WARNING)
    stream.setFormatter(formatter)
    logger.addHandler(stream)

    return logger


def log_event(logger: logging.Logger, event: str, details: Optional[Dict[str, Any]] = None) -> None:
    payload = {"event": event}
    if details:
        payload.update(details)
    logger.info(json.dumps(payload, ensure_ascii=False))
