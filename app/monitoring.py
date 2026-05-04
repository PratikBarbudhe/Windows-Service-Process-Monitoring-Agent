from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone

import psutil

from app.config import settings
from app.models import Alert, ProcessInfo, ScanResult

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
                entries.append(
                    ProcessInfo(
                        pid=proc.info["pid"],
                        name=proc.info.get("name") or "unknown",
                        username=proc.info.get("username"),
                        exe=proc.info.get("exe"),
                        cpu_percent=round(cpu, 2),
                        memory_mb=round(mem, 2),
                    )
                )
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
        return sorted(entries, key=lambda item: (item.cpu_percent, item.memory_mb), reverse=True)

    def _detect_alerts(self, processes: list[ProcessInfo]) -> list[Alert]:
        alerts: list[Alert] = []
        for proc in processes:
            if proc.cpu_percent >= 85:
                alerts.append(
                    Alert(
                        type="High CPU Usage",
                        severity="HIGH",
                        message=f"{proc.name} is using {proc.cpu_percent:.1f}% CPU",
                        process_name=proc.name,
                        pid=proc.pid,
                    )
                )
            if proc.memory_mb >= 1024:
                alerts.append(
                    Alert(
                        type="High Memory Usage",
                        severity="MEDIUM",
                        message=f"{proc.name} is using {proc.memory_mb:.1f} MB memory",
                        process_name=proc.name,
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

