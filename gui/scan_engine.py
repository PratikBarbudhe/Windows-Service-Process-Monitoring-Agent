"""
Headless monitoring scan for the GUI (no console spam).

Runs the same detection pipeline as the CLI agent (minus session-only signature
tracking) and returns structured rows for tables and charts.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

import psutil

import config
from alert_manager import AlertManager
from demo_scenarios import get_simulated_alerts
from process_analyzer import ProcessAnalyzer
from report_generator import ReportGenerator
from path_utils import ensure_alert_path_field
from service_auditor import ServiceAuditor


def _serialize_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    row = dict(ensure_alert_path_field(dict(alert)))
    ts = row.get("timestamp")
    if isinstance(ts, datetime):
        row["timestamp"] = ts.strftime("%Y-%m-%d %H:%M:%S")
    return row


def _service_row_suspicious(path: str) -> bool:
    pl = (path or "").lower()
    for frag in config.SUSPICIOUS_PATH_FRAGMENTS:
        if frag.lower() in pl:
            return True
    if pl.endswith((".bat", ".cmd", ".ps1", ".vbs", ".js")):
        return True
    return False


@dataclass
class ScanSnapshot:
    """Result bundle consumed by the PyQt worker and main window."""

    processes: List[Dict[str, Any]] = field(default_factory=list)
    services: List[Dict[str, Any]] = field(default_factory=list)
    alerts: List[Dict[str, Any]] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)
    alert_file: Optional[str] = None
    error: Optional[str] = None


def run_full_scan(*, persist: bool = True, simulate: bool = False) -> ScanSnapshot:
    """
    Execute process + service analysis and optional disk export.

    Args:
        persist: Write alerts/summary/detailed reports like the CLI.
        simulate: Append demonstration alerts (portfolio mode).
    """
    snap = ScanSnapshot()
    try:
        alert_manager = AlertManager(dedup=False)
        alert_manager.start_new_scan()
        pa = ProcessAnalyzer()
        sa = ServiceAuditor()

        pa.enumerate_processes()
        pa.build_process_tree()

        alert_manager.add_alerts(pa.detect_suspicious_relationships())
        alert_manager.add_alerts(pa.detect_unauthorized_processes())
        alert_manager.add_alerts(pa.detect_suspicious_cmdlines())
        alert_manager.add_alerts(pa.detect_process_injection_signs())
        alert_manager.add_alerts(pa.detect_orphan_processes())
        alert_manager.add_alerts(pa.detect_duplicate_names())

        sa.enumerate_services()
        alert_manager.add_alerts(sa.detect_suspicious_services())

        if simulate:
            alert_manager.add_alerts(get_simulated_alerts())

        # Brief pause so per-PID cpu_percent() has a meaningful sample on many systems.
        time.sleep(0.12)

        for pid, info in pa.processes.items():
            cpu_val = 0.0
            try:
                cpu_val = float(psutil.Process(pid).cpu_percent(interval=None))
            except (psutil.Error, OSError):
                pass
            mem_mb = round(info.memory_rss_bytes / (1024 * 1024), 2) if info.memory_rss_bytes else 0.0
            snap.processes.append(
                {
                    "pid": pid,
                    "name": info.name,
                    "path": info.exe_path,
                    "cpu": round(cpu_val, 2),
                    "memory_mb": mem_mb,
                    "username": info.username,
                }
            )

        suspicious_services: Set[str] = set()
        for a in alert_manager.get_all_alerts():
            sn = a.get("service_name")
            if sn and "service" in str(a.get("type", "")).lower():
                suspicious_services.add(str(sn))

        for name, si in sorted(sa.services.items(), key=lambda x: x[0].lower()):
            path = si.exe_path or ""
            heur = _service_row_suspicious(path)
            susp = name in suspicious_services or heur
            snap.services.append(
                {
                    "name": name,
                    "display_name": si.display_name,
                    "status": si.status,
                    "start_type": si.start_type,
                    "path": path,
                    "suspicious": susp,
                }
            )

        snap.alerts = [_serialize_alert(a) for a in alert_manager.get_all_alerts()]
        snap.statistics = alert_manager.get_statistics()

        if persist:
            snap.alert_file = alert_manager.save_alerts_to_file(quiet=True)
            rg = ReportGenerator(pa, sa, alert_manager)
            rg.generate_summary_report()
            rg.generate_detailed_report()

        return snap
    except Exception as exc:  # noqa: BLE001 — surface to GUI
        snap.error = str(exc)
        return snap


def load_alerts_json(path: str) -> Optional[Dict[str, Any]]:
    """Load alerts payload written by ``AlertManager.save_alerts_to_file``."""
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def latest_alerts_json_path(log_dir: str = config.LOG_DIRECTORY) -> Optional[str]:
    """Return path to newest ``alerts_*.json`` by modification time."""
    if not os.path.isdir(log_dir):
        return None
    files = [
        os.path.join(log_dir, f)
        for f in os.listdir(log_dir)
        if f.startswith("alerts_") and f.endswith(".json")
    ]
    if not files:
        return None
    return max(files, key=os.path.getmtime)
