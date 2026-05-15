from __future__ import annotations

import json
import logging
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import psutil

from app.config import settings
from app.models import Alert, ProcessInfo, ScanResult

logger = logging.getLogger(__name__)

# Processes that must never trigger CPU alerts (still listed with PID).
_NON_ALERT_CPU_NAMES = frozenset({"system idle process", "idle"})

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


def should_skip_high_cpu_alert(*, name: str, display_name: str) -> bool:
    """Skip alert generation for known false-positive CPU processes only."""
    for candidate in (name, display_name):
        if candidate and candidate.strip().lower() in _NON_ALERT_CPU_NAMES:
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


class MonitoringAgent:
    def __init__(self) -> None:
        self._alerts: list[Alert] = []
        settings.output_dir.mkdir(parents=True, exist_ok=True)
        settings.log_dir.mkdir(parents=True, exist_ok=True)
        settings.report_dir.mkdir(parents=True, exist_ok=True)

    @property
    def alerts(self) -> list[Alert]:
        return self._alerts

    def run_scan(self) -> ScanResult:
        processes = self._enumerate_processes()
        alerts = self._detect_alerts(processes)
        self._alerts = alerts
        result = ScanResult(processes=processes, alerts=alerts)
        self._persist_result(result)
        logger.info("Scan complete: %s processes, %s alerts", len(processes), len(alerts))
        return result

    def get_process_snapshot(self) -> list[dict]:
        """Return current process snapshot without generating alerts/reports."""
        return [item.to_dict() for item in self._enumerate_processes()]

    def load_latest_alerts(self) -> list[dict]:
        """Load alerts from the latest persisted scan payload."""
        latest_file = settings.log_dir / "alerts_latest.json"
        if not latest_file.exists():
            return []
        try:
            payload = json.loads(latest_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            logger.warning("Could not parse %s", latest_file)
            return []
        return payload.get("alerts", [])

    def _enumerate_processes(self) -> list[ProcessInfo]:
        entries: list[ProcessInfo] = []
        procs = list(psutil.process_iter(["pid", "name", "username", "exe", "memory_info"]))

        # Prime CPU counters first, then sample again after a short interval.
        for proc in procs:
            try:
                proc.cpu_percent(interval=None)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue

        time.sleep(0.25)

        for proc in procs:
            try:
                mem = proc.info["memory_info"].rss / 1024 / 1024 if proc.info.get("memory_info") else 0.0
                cpu = float(proc.cpu_percent(interval=None))
                row = build_process_row(proc, cpu_percent=cpu, memory_mb=mem)
                entries.append(
                    ProcessInfo(
                        pid=row["pid"],
                        name=row["name"],
                        display_name=row["display_name"],
                        username=row.get("username"),
                        exe=row.get("exe"),
                        cpu_percent=row["cpu_percent"],
                        memory_mb=row["memory_mb"],
                    )
                )
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue

        group_labels = attach_group_labels([item.name for item in entries])
        for item, group_label in zip(entries, group_labels, strict=True):
            item.group_label = group_label

        return sorted(entries, key=lambda item: (item.cpu_percent, item.memory_mb), reverse=True)

    def _detect_alerts(self, processes: list[ProcessInfo]) -> list[Alert]:
        alerts: list[Alert] = []
        for proc in processes:
            label = proc.display_name or proc.name
            if proc.cpu_percent >= 85 and not should_skip_high_cpu_alert(
                name=proc.name,
                display_name=label,
            ):
                alerts.append(
                    Alert(
                        type="High CPU Usage",
                        severity="HIGH",
                        message=(
                            f"{label} (PID {proc.pid}) is using {proc.cpu_percent:.1f}% CPU"
                        ),
                        process_name=label,
                        pid=proc.pid,
                    )
                )
            if proc.memory_mb >= 1024:
                alerts.append(
                    Alert(
                        type="High Memory Usage",
                        severity="MEDIUM",
                        message=(
                            f"{label} (PID {proc.pid}) is using {proc.memory_mb:.1f} MB memory"
                        ),
                        process_name=label,
                        pid=proc.pid,
                    )
                )
        return alerts

    def _persist_result(self, result: ScanResult) -> None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        result_path = settings.log_dir / f"scan_{ts}.json"
        alerts_path = settings.log_dir / "alerts_latest.json"

        payload = result.to_dict()
        result_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        alerts_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
