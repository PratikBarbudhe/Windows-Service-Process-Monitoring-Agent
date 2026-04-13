"""
Shared helpers for executable paths on alerts (CLI, JSON, GUI).

Keeps ``path`` as the canonical binary location field while remaining compatible
with older logs that only stored ``child_path`` or omitted path entirely.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

# Substrings that commonly indicate staging / user-writable execution (case-insensitive).
_SUSPICIOUS_FRAGMENTS = (
    "\\appdata\\",
    "\\temp\\",
    "\\tmp\\",
    ":\\windows\\temp",
    "\\downloads\\",
    "\\users\\public",
    "\\startup\\",
    "\\inetcache\\",
)


def resolve_alert_path(alert: Dict[str, Any]) -> str:
    """Best-effort full path string for display and export."""
    for key in ("path", "child_path", "exe_path"):
        v = alert.get(key)
        if v and str(v).strip() and str(v).strip().upper() != "N/A":
            return str(v).strip()
    return ""


def ensure_alert_path_field(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return a copy where ``path`` is always set (possibly empty).

    Older JSON may omit ``path``; ``child_path`` / ``exe_path`` are merged in.
    """
    a = dict(alert)
    a["path"] = resolve_alert_path(a)
    return a


def is_suspicious_path(path: Optional[str]) -> bool:
    """Heuristic: user-writable / staging locations."""
    if not path or path.upper() == "N/A":
        return False
    pl = path.lower().replace("/", "\\")
    return any(frag in pl for frag in _SUSPICIOUS_FRAGMENTS)


def truncate_path_display(path: str, max_len: int = 72) -> str:
    """Middle-ellipsis truncation for dense tables."""
    path = path.strip()
    if len(path) <= max_len:
        return path
    keep = max_len // 2 - 2
    return path[:keep] + " … " + path[-keep:]
