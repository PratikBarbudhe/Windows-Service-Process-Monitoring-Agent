"""
Monitoring agent: scan processes, detect alerts, write logs.

Process naming and CPU math live in app.process_display — edit that file to
change how names or CPU percentages work.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone

import psutil

from app.config import settings
from app.models import Alert, ProcessInfo, ScanResult
from app.process_display import (
    attach_group_labels,
    build_process_row,
    normalize_cpu_percent,
    should_skip_high_cpu_alert,
)

logger = logging.getLogger(__name__)


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

        for proc in procs:
            try:
                proc.cpu_percent(interval=None)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue

        time.sleep(max(settings.cpu_sample_seconds, 0.5))

        for proc in procs:
            try:
                mem = proc.info["memory_info"].rss / 1024 / 1024 if proc.info.get("memory_info") else 0.0
                raw_cpu = float(proc.cpu_percent(interval=None))
                cpu = normalize_cpu_percent(raw_cpu)
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
        threshold = settings.cpu_alert_threshold
        for proc in processes:
            label = proc.display_name or proc.name
            if proc.cpu_percent >= threshold and not should_skip_high_cpu_alert(
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
