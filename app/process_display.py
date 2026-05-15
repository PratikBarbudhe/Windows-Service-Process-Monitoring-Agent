"""
Process display names and CPU normalization.

This module is the single place to change how processes appear in the UI
(Task Manager-style names, group labels) and how CPU % is calculated for alerts.

Used by: app.monitoring, dashboard.dashboard_streamlit
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path
from typing import Any, Optional

import psutil

# Processes that must never trigger CPU alerts (still listed with PID).
_NON_ALERT_CPU_NAMES = frozenset({"system idle process", "idle"})

# Agent stack processes — expected load, not actionable host alerts.
_AGENT_EXE_NAMES = frozenset(
    {
        "uvicorn.exe",
        "uvicorn",
        "streamlit.exe",
        "streamlit",
    }
)
_AGENT_DISPLAY_MARKERS = (
    "monitoring.py",
    "dashboard_streamlit.py",
    "api_server",
    "windows-service-process-monitoring-agent",
)

_SCRIPT_SUFFIXES = {".py", ".js", ".ts", ".ps1", ".bat", ".cmd", ".vbs", ".jar"}
_INTERPRETER_NAMES = frozenset(
    {
        "python.exe",
        "pythonw.exe",
        "python",
        "pythonw",
        "node.exe",
        "node",
        "pwsh.exe",
        "powershell.exe",
        "cmd.exe",
    }
)


def cpu_count_logical() -> int:
    return psutil.cpu_count(logical=True) or 1


def normalize_cpu_percent(raw_percent: float) -> float:
    """
    Convert psutil per-core CPU (can exceed 100%) to Task Manager-style
    percentage of total system capacity (0–100).
    """
    cores = cpu_count_logical()
    normalized = raw_percent / cores
    return round(min(max(normalized, 0.0), 100.0), 2)


def get_cmdline(proc: psutil.Process) -> list[str]:
    try:
        return proc.cmdline() or []
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        return []


def _truncate(value: str, max_len: int = 24) -> str:
    if len(value) <= max_len:
        return value
    return value[: max_len - 3] + "..."


def _window_title_for_pid(pid: int) -> Optional[str]:
    if sys.platform != "win32":
        return None
    try:
        import win32gui
        import win32process
    except ImportError:
        return None

    titles: list[str] = []

    def _callback(hwnd: int, _: Any) -> bool:
        if not win32gui.IsWindowVisible(hwnd):
            return True
        _, found_pid = win32process.GetWindowThreadProcessId(hwnd)
        if found_pid != pid:
            return True
        title = (win32gui.GetWindowText(hwnd) or "").strip()
        if title:
            titles.append(title)
        return True

    try:
        win32gui.EnumWindows(_callback, None)
    except Exception:
        return None
    return titles[0] if titles else None


def _suffix_hint(*, exe: Optional[str], cmdline: list[str]) -> str:
    for arg in cmdline[1:]:
        if arg.lower().endswith(".py"):
            parent = Path(arg).resolve().parent.name
            if parent and parent.lower() not in {"scripts", "bin", "lib"}:
                return _truncate(parent)
    if exe:
        parent = Path(exe).parent.name
        if parent.lower() not in {
            "python",
            "python311",
            "python312",
            "python313",
            "scripts",
            "bin",
            "system32",
        }:
            return _truncate(parent)
    return ""


def resolve_display_name(
    *,
    pid: int,
    name: str,
    exe: Optional[str] = None,
    cmdline: Optional[list[str]] = None,
    window_title: Optional[str] = None,
) -> str:
    """Build a Task Manager-style display name for a single process instance."""
    exe_name = (name or "unknown").strip()
    cmd = cmdline or []
    lowered_exe = exe_name.lower()
    lowered_cmd = [part.lower() for part in cmd]

    if window_title is None:
        window_title = _window_title_for_pid(pid)

    if "-m" in lowered_cmd:
        module_index = lowered_cmd.index("-m")
        if module_index + 1 < len(cmd):
            module_name = Path(cmd[module_index + 1]).name
            hint = _suffix_hint(exe=exe, cmdline=cmd)
            if hint:
                return f"{module_name} - {hint}"
            return module_name

    if "-c" in lowered_cmd:
        return app_group_label(exe_name)

    for arg in cmd[1:]:
        arg_path = Path(arg)
        if arg_path.suffix.lower() in _SCRIPT_SUFFIXES:
            script = arg_path.name
            hint = _suffix_hint(exe=exe, cmdline=cmd)
            if not hint and window_title:
                hint = _truncate(window_title.split(" - ")[0])
            if hint:
                return f"{script} - {hint}"
            return script

    if lowered_exe in _INTERPRETER_NAMES or any(
        lowered_exe.endswith(suffix) for suffix in _INTERPRETER_NAMES
    ):
        for arg in cmd[1:]:
            if arg.startswith("-") or arg.startswith("/"):
                continue
            candidate = Path(arg).name
            if candidate and candidate.lower() != lowered_exe:
                hint = _suffix_hint(exe=exe, cmdline=cmd)
                if hint:
                    return f"{candidate} - {hint}"
                return candidate

    if len(cmd) >= 2:
        candidate = cmd[1]
        if (
            not candidate.startswith(("-", "/"))
            and len(candidate) < 160
            and "\n" not in candidate
            and ";" not in candidate
        ):
            base = Path(candidate).name
            if base and base.lower() not in {lowered_exe, Path(lowered_exe).stem.lower()}:
                return base

    if exe:
        return Path(exe).name

    return exe_name


def app_group_label(exe_name: str) -> str:
    """Friendly group key used for Task Manager-style '(N)' suffixes."""
    stem = Path(exe_name or "unknown").stem
    if not stem:
        return "Unknown"
    return stem[0].upper() + stem[1:]


def attach_group_labels(exe_names: list[str]) -> list[str]:
    """Return group labels like 'Python (3)' when multiple processes share an exe family."""
    group_keys = [app_group_label(name) for name in exe_names]
    counts = Counter(group_keys)
    labels: list[str] = []
    for key in group_keys:
        count = counts[key]
        labels.append(f"{key} ({count})" if count > 1 else key)
    return labels


def should_skip_high_cpu_alert(
    *,
    name: str,
    display_name: str,
    cmdline: Optional[list[str]] = None,
) -> bool:
    """Skip alert generation for known false-positive CPU processes only."""
    lowered_name = (name or "").strip().lower()
    lowered_display = (display_name or "").strip().lower()

    for candidate in (lowered_name, lowered_display):
        if candidate in _NON_ALERT_CPU_NAMES:
            return True

    if lowered_name in _AGENT_EXE_NAMES:
        return True

    for marker in _AGENT_DISPLAY_MARKERS:
        if marker in lowered_display:
            return True

    if cmdline:
        joined = " ".join(cmdline).lower()
        for marker in _AGENT_DISPLAY_MARKERS:
            if marker in joined:
                return True
        if "uvicorn" in joined and "api" in joined:
            return True

    return False


def build_process_row(proc: psutil.Process, *, cpu_percent: float, memory_mb: float) -> dict[str, Any]:
    """Snapshot one process with Task Manager-style naming; always includes pid."""
    info = proc.info
    pid = int(info["pid"])
    name = info.get("name") or "unknown"
    exe = info.get("exe")
    cmdline = get_cmdline(proc)
    display_name = resolve_display_name(pid=pid, name=name, exe=exe, cmdline=cmdline)
    return {
        "pid": pid,
        "name": name,
        "display_name": display_name,
        "username": info.get("username"),
        "exe": exe,
        "cpu_percent": round(cpu_percent, 2),
        "memory_mb": round(memory_mb, 2),
    }
