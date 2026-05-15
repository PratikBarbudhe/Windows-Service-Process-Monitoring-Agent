"""Shared application constants."""

from __future__ import annotations

# Human-readable refresh labels mapped to seconds (10 sec → 10 min).
REFRESH_INTERVALS: dict[str, int] = {
    "10 sec": 10,
    "30 sec": 30,
    "1 min": 60,
    "2 min": 120,
    "5 min": 300,
    "10 min": 600,
}

DEFAULT_REFRESH_LABEL = "10 sec"
TOP_RESOURCE_LIMIT = 5
