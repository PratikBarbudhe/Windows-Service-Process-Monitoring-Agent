"""
Rank and select top resource-consuming processes for the dashboard.
"""

from __future__ import annotations

from typing import Any, Literal

SortMetric = Literal["cpu", "memory"]

_METRIC_KEYS: dict[SortMetric, str] = {
    "cpu": "cpu_percent",
    "memory": "memory_mb",
}


def _display_label(row: dict[str, Any]) -> str:
    return str(row.get("display_name") or row.get("name") or "unknown")


def rank_top_processes(
    processes: list[dict[str, Any]],
    *,
    sort_by: SortMetric = "cpu",
    limit: int = 5,
) -> list[dict[str, Any]]:
    """Return the top N processes by CPU or memory usage."""
    if not processes:
        return []

    metric_key = _METRIC_KEYS[sort_by]
    ranked = sorted(
        processes,
        key=lambda row: float(row.get(metric_key, 0) or 0),
        reverse=True,
    )
    top = ranked[: max(limit, 0)]
    return [
        {
            "rank": index,
            "pid": row.get("pid"),
            "display_name": _display_label(row),
            "name": row.get("name"),
            "cpu_percent": round(float(row.get("cpu_percent", 0) or 0), 2),
            "memory_mb": round(float(row.get("memory_mb", 0) or 0), 2),
            "group_label": row.get("group_label"),
        }
        for index, row in enumerate(top, start=1)
    ]
