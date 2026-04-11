"""
Human-readable and machine-readable reporting: summary, detailed text, and CSV export.
"""

from __future__ import annotations

import csv
import json
import os
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional

import config

if TYPE_CHECKING:
    from alert_manager import AlertManager
    from process_analyzer import ProcessAnalyzer
    from service_auditor import ServiceAuditor


class ReportGenerator:
    """Builds SOC-friendly artifacts from analyzers and the alert manager."""

    def __init__(
        self,
        process_analyzer: "ProcessAnalyzer",
        service_auditor: "ServiceAuditor",
        alert_manager: "AlertManager",
    ) -> None:
        self.process_analyzer = process_analyzer
        self.service_auditor = service_auditor
        self.alert_manager = alert_manager

    def _serialize_alert_row(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        row = dict(alert)
        ts = row.get("timestamp")
        if isinstance(ts, datetime):
            row["timestamp"] = ts.strftime("%Y-%m-%d %H:%M:%S")
        return row

    def generate_summary_report(self, filename: Optional[str] = None) -> str:
        """Short executive summary (text)."""
        if filename is None:
            filename = f"monitoring_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        os.makedirs(config.REPORT_DIRECTORY, exist_ok=True)
        filepath = os.path.join(config.REPORT_DIRECTORY, filename)
        stats = self.alert_manager.get_statistics()

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("WINDOWS MONITORING AGENT — SUMMARY\n")
            f.write("=" * 80 + "\n")
            f.write(f"Generated: {datetime.now():%Y-%m-%d %H:%M:%S}\n\n")
            f.write(f"Processes sampled: {len(self.process_analyzer.processes)}\n")
            f.write(f"Services enumerated: {len(self.service_auditor.services)}\n")
            f.write(f"Alerts: {stats['total_alerts']}\n")
            f.write(
                f"  Critical={stats['critical']} High={stats['high']} "
                f"Medium={stats['medium']} Low={stats['low']} Info={stats['info']}\n"
            )
            if stats.get("duplicates_suppressed"):
                f.write(f"Dedup suppressed (session): {stats['duplicates_suppressed']}\n")
            f.write("\nTop findings:\n")
            for a in self.alert_manager.get_all_alerts()[:15]:
                f.write(
                    f" - [{a.get('severity')}] {a.get('type')}: "
                    f"{a.get('reason') or a.get('description', '')}\n"
                )
            if stats["total_alerts"] == 0:
                f.write(" - No findings in this window.\n")
        return filepath

    def generate_detailed_report(self, filename: Optional[str] = None) -> str:
        """Full narrative report (text)."""
        if filename is None:
            filename = f"monitoring_detailed_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        os.makedirs(config.REPORT_DIRECTORY, exist_ok=True)
        filepath = os.path.join(config.REPORT_DIRECTORY, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 100 + "\n")
            f.write("WINDOWS SERVICE & PROCESS MONITORING — DETAILED REPORT\n")
            f.write("=" * 100 + "\n")
            f.write(f"Generated: {datetime.now():%Y-%m-%d %H:%M:%S}\n\n")

            stats = self.alert_manager.get_statistics()
            f.write("EXECUTIVE SUMMARY\n")
            f.write("-" * 100 + "\n")
            f.write(f"Processes: {len(self.process_analyzer.processes)}\n")
            f.write(f"Services: {len(self.service_auditor.services)}\n")
            f.write(f"Alerts: {stats['total_alerts']}\n\n")

            f.write("ALERTS (severity-sorted)\n")
            f.write("-" * 100 + "\n")
            if not self.alert_manager.alerts:
                f.write("No alerts.\n\n")
            else:
                for i, alert in enumerate(self.alert_manager.get_all_alerts(), 1):
                    f.write(f"\n#{i} [{alert.get('severity')}] risk={alert.get('risk_score')}\n")
                    f.write(f"Type: {alert.get('type')}\n")
                    f.write(f"Time: {alert.get('timestamp')}\n")
                    f.write(f"Reason: {alert.get('reason') or alert.get('description')}\n")
                    for k, v in sorted(alert.items()):
                        if k in {"type", "severity", "timestamp", "description", "reason", "risk_score"}:
                            continue
                        f.write(f"  {k}: {v}\n")

            f.write("\n" + "=" * 100 + "\nPROCESS TELEMETRY SNAPSHOT\n")
            f.write("-" * 100 + "\n")
            for pid, p in sorted(self.process_analyzer.processes.items())[:40]:
                f.write(
                    f"PID {pid:>6} | {p.name:<20} | PPID {p.ppid:<6} | "
                    f"RSS {p.memory_rss_bytes // 1024:>6} KiB | {p.exe_path[:80]}\n"
                )
            if len(self.process_analyzer.processes) > 40:
                f.write(f"... ({len(self.process_analyzer.processes) - 40} more processes omitted)\n")

            f.write("\n" + "=" * 100 + "\nAUTO-START SERVICES (count)\n")
            f.write("-" * 100 + "\n")
            startup = self.service_auditor.get_startup_services()
            f.write(f"Total auto/boot/system services: {len(startup)}\n")

            f.write("\n" + "=" * 100 + "\nRECOMMENDATIONS\n")
            f.write("-" * 100 + "\n")
            if stats["critical"]:
                f.write("Critical findings: isolate host from sensitive networks and escalate.\n")
            elif stats["high"]:
                f.write("High findings: collect command lines, parent chains, and EDR telemetry.\n")
            elif stats["medium"]:
                f.write("Medium findings: validate binaries against change control / software inventory.\n")
            else:
                f.write("No major findings: maintain baselines and scheduled reviews.\n")

            f.write("\nEND OF REPORT\n")
        return filepath

    def generate_text_report(self, filename: Optional[str] = None) -> str:
        """Backwards-compatible alias: detailed report."""
        return self.generate_detailed_report(filename)

    def export_alerts_csv(self, filename: Optional[str] = None) -> str:
        """Flatten alerts for spreadsheets or SIEM staging."""
        if filename is None:
            filename = f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        os.makedirs(config.REPORT_DIRECTORY, exist_ok=True)
        filepath = os.path.join(config.REPORT_DIRECTORY, filename)

        fieldnames = [
            "timestamp",
            "severity",
            "risk_score",
            "type",
            "process_name",
            "service_name",
            "pid",
            "child_pid",
            "path",
            "cmdline",
            "username",
            "reason",
        ]
        with open(filepath, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for alert in self.alert_manager.get_all_alerts():
                row = self._serialize_alert_row(alert)
                path_val = row.get("path") or row.get("child_path") or ""
                writer.writerow(
                    {
                        "timestamp": row.get("timestamp"),
                        "severity": row.get("severity"),
                        "risk_score": row.get("risk_score"),
                        "type": row.get("type"),
                        "process_name": row.get("process_name") or row.get("child_name"),
                        "service_name": row.get("service_name"),
                        "pid": row.get("pid"),
                        "child_pid": row.get("child_pid"),
                        "path": path_val,
                        "cmdline": row.get("cmdline"),
                        "username": row.get("username"),
                        "reason": row.get("reason") or row.get("description"),
                    }
                )
        return filepath

    def write_scan_json(self, filename: Optional[str] = None) -> str:
        """Structured JSON snapshot including counts and serialized alerts."""
        if filename is None:
            filename = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        os.makedirs(config.LOG_DIRECTORY, exist_ok=True)
        filepath = os.path.join(config.LOG_DIRECTORY, filename)
        payload = {
            "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "process_count": len(self.process_analyzer.processes),
            "service_count": len(self.service_auditor.services),
            "statistics": self.alert_manager.get_statistics(),
            "alerts": [self._serialize_alert_row(a) for a in self.alert_manager.get_all_alerts()],
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        return filepath

    def generate_summary(self) -> str:
        stats = self.alert_manager.get_statistics()
        return (
            f"Processes={len(self.process_analyzer.processes)} "
            f"Services={len(self.service_auditor.services)} "
            f"Alerts={stats['total_alerts']} "
            f"(C/H/M/L/I)="
            f"{stats['critical']}/{stats['high']}/{stats['medium']}/{stats['low']}/{stats['info']}"
        )
