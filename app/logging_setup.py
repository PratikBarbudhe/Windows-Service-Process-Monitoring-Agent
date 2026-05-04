from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler

from app.config import settings


def configure_logging() -> None:
    settings.log_dir.mkdir(parents=True, exist_ok=True)
    log_file = settings.log_dir / "agent.log"

    root_logger = logging.getLogger()
    if root_logger.handlers:
        return

    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    stream_handler.setLevel(level)

    file_handler = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=3)
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)

    root_logger.setLevel(level)
    root_logger.addHandler(stream_handler)
    root_logger.addHandler(file_handler)

