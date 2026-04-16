"""
Alert aggregation: severity ordering, deduplication, console colors, JSON export, and file logging.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from colorama import Fore, Style, init

import config
from path_utils import ensure_alert_path_field

init(autoreset=True)

logger = logging.getLogger(__name__)


def _ensure_agent_logging(log_dir: str = config.LOG_DIRECTORY) -> None:
    """Attach a rotating-friendly file handler once, and reconfigure it if the log path changes."""
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "agent.log")
    root = logging.getLogger()

    existing_handler = getattr(root, "_agent_file_handler", None)
    existing_dir = getattr(root, "_agent_file_handler_dir", None)
    if getattr(root, "_agent_file_handler_configured", False) and existing_dir == log_dir:
        return

    if existing_handler is not None:
        root.removeHandler(existing_handler)

    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.INFO)
    fh.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")
    )
    root.addHandler(fh)
    root.setLevel(min(root.level or logging.INFO, logging.INFO))
    setattr(root, "_agent_file_handler_configured", True)
    setattr(root, "_agent_file_handler", fh)
    setattr(root, "_agent_file_handler_dir", log_dir)


class AlertManager:
    """Collects alerts, deduplicates, prints colorized summaries, and persists JSON."""

    def __init__(self, dedup: bool = False) -> None:
        _ensure_agent_logging()
        self.alerts: List[Dict[str, Any]] = []
        self.dedup_enabled = dedup
        self._seen_fingerprints: Set[str] = set()
        self.duplicates_suppressed = 0
        self.alert_counts: Dict[str, int] = {
            config.SEVERITY_CRITICAL: 0,
            config.SEVERITY_HIGH: 0,
            config.SEVERITY_MEDIUM: 0,
            config.SEVERITY_LOW: 0,
            config.SEVERITY_INFO: 0,
        }


def _fingerprint(alert: Dict[str, Any]) -> str:
    """Stable hash for cross-scan deduplication."""
    parts: Tuple[Any, ...] = (
        alert.get("type"),
        alert.get("severity"),
        alert.get("child_pid"),
        alert.get("pid"),
        alert.get("service_name"),
        alert.get("process_name"),
        alert.get("path") or alert.get("child_path"),
        alert.get("description"),
    )
    raw = "|".join(str(p) for p in parts)
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


class AlertManager:
    """Collects alerts, deduplicates, prints colorized summaries, and persists JSON."""

    def __init__(self, dedup: bool = False) -> None:
        self.alerts: List[Dict[str, Any]] = []
        self.dedup_enabled = dedup
        self._seen_fingerprints: Set[str] = set()
        self.duplicates_suppressed = 0
        self.alert_counts: Dict[str, int] = {
            config.SEVERITY_CRITICAL: 0,
            config.SEVERITY_HIGH: 0,
            config.SEVERITY_MEDIUM: 0,
            config.SEVERITY_LOW: 0,
            config.SEVERITY_INFO: 0,
        }

    def clear_session_dedup(self) -> None:
        """Reset deduplication memory (for explicit new sessions)."""
        self._seen_fingerprints.clear()
        self.duplicates_suppressed = 0

    def start_new_scan(self) -> None:
        """Clear current scan buffers while optionally retaining dedup fingerprints."""
        self.alerts = []
        self.duplicates_suppressed = 0
        self.alert_counts = {
            config.SEVERITY_CRITICAL: 0,
            config.SEVERITY_HIGH: 0,
            config.SEVERITY_MEDIUM: 0,
            config.SEVERITY_LOW: 0,
            config.SEVERITY_INFO: 0,
        }

    def _normalize_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        a = ensure_alert_path_field(dict(alert))
        if "reason" not in a and "description" in a:
            a["reason"] = a["description"]
        if "description" not in a and "reason" in a:
            a["description"] = a["reason"]
        sev = a.get("severity", config.SEVERITY_INFO)
        if "risk_score" not in a:
            a["risk_score"] = config.RISK_SCORES.get(str(sev), 10)
        return a

    def add_alert(self, alert: Dict[str, Any]) -> bool:
        """
        Add a single alert. Returns True if stored, False if suppressed as duplicate.
        """
        alert = self._normalize_alert(alert)
        fp = _fingerprint(alert)
        if self.dedup_enabled and fp in self._seen_fingerprints:
            self.duplicates_suppressed += 1
            logger.info("Duplicate alert suppressed: %s", alert.get("type"))
            return False
        if self.dedup_enabled:
            self._seen_fingerprints.add(fp)

        self.alerts.append(alert)
        severity = str(alert.get("severity", config.SEVERITY_INFO))
        if severity in self.alert_counts:
            self.alert_counts[severity] += 1
        logger.info(
            "Alert [%s] %s — %s",
            severity,
            alert.get("type"),
            alert.get("reason") or alert.get("description", ""),
        )
        return True

    def add_alerts(self, alerts: Iterable[Dict[str, Any]]) -> int:
        """Add many alerts; returns count of newly stored alerts."""
        added = 0
        for a in alerts:
            if self.add_alert(a):
                added += 1
        return added

    def get_alerts_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        return [a for a in self.alerts if a.get("severity") == severity]

    def get_all_alerts(self) -> List[Dict[str, Any]]:
        severity_order = {
            config.SEVERITY_CRITICAL: 0,
            config.SEVERITY_HIGH: 1,
            config.SEVERITY_MEDIUM: 2,
            config.SEVERITY_LOW: 3,
            config.SEVERITY_INFO: 4,
        }
        return sorted(
            self.alerts,
            key=lambda x: (
                severity_order.get(str(x.get("severity", config.SEVERITY_INFO)), 5),
                x.get("timestamp", datetime.now()),
            ),
        )

    def print_alert(self, alert: Dict[str, Any]) -> None:
        severity = str(alert.get("severity", config.SEVERITY_INFO))
        color_map = {
            config.SEVERITY_CRITICAL: Fore.RED,
            config.SEVERITY_HIGH: Fore.LIGHTRED_EX,
            config.SEVERITY_MEDIUM: Fore.YELLOW,
            config.SEVERITY_LOW: Fore.CYAN,
            config.SEVERITY_INFO: Fore.WHITE,
        }
        color = color_map.get(severity, Fore.WHITE)
        risk = alert.get("risk_score", "")

        print(f"\n{color}{'=' * 80}")
        print(f"[{severity}] {alert.get('type', 'Unknown')}" + (f" | risk={risk}" if risk != "" else ""))
        print(f"Time: {alert.get('timestamp', 'N/A')}")
        print(f"Reason: {alert.get('reason') or alert.get('description', 'N/A')}")

        for key, value in sorted(alert.items()):
            if key in {"type", "severity", "timestamp", "description", "reason", "risk_score"}:
                continue
            print(f"{key.replace('_', ' ').title()}: {value}")
        print(f"{'=' * 80}{Style.RESET_ALL}")

    def print_all_alerts(self) -> None:
        if not self.alerts:
            print(f"\n{Fore.GREEN}No alerts in this scan window.{Style.RESET_ALL}")
            if self.dedup_enabled and self.duplicates_suppressed:
                print(
                    f"{Fore.CYAN}({self.duplicates_suppressed} duplicate(s) suppressed vs prior scans){Style.RESET_ALL}"
                )
            return

        print(f"\n{Fore.RED}{'=' * 80}")
        print("ALERT SUMMARY")
        print(f"{'=' * 80}{Style.RESET_ALL}")
        print(f"Total Alerts: {len(self.alerts)}")
        if self.dedup_enabled and self.duplicates_suppressed:
            print(f"Duplicates suppressed this scan: {self.duplicates_suppressed}")
        print(f"  {Fore.RED}Critical: {self.alert_counts[config.SEVERITY_CRITICAL]}{Style.RESET_ALL}")
        print(f"  {Fore.LIGHTRED_EX}High: {self.alert_counts[config.SEVERITY_HIGH]}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}Medium: {self.alert_counts[config.SEVERITY_MEDIUM]}{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}Low: {self.alert_counts[config.SEVERITY_LOW]}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Info: {self.alert_counts[config.SEVERITY_INFO]}{Style.RESET_ALL}")

        for alert in self.get_all_alerts():
            self.print_alert(alert)

    def save_alerts_to_file(self, filename: Optional[str] = None, *, quiet: bool = False) -> str:
        if filename is None:
            filename = f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        os.makedirs(config.LOG_DIRECTORY, exist_ok=True)
        filepath = os.path.join(config.LOG_DIRECTORY, filename)

        serializable: List[Dict[str, Any]] = []
        for alert in self.alerts:
            row = dict(alert)
            ts = row.get("timestamp")
            if isinstance(ts, datetime):
                row["timestamp"] = ts.strftime("%Y-%m-%d %H:%M:%S")
            serializable.append(row)

        payload = {
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_alerts": len(self.alerts),
            "severity_breakdown": dict(self.alert_counts),
            "duplicates_suppressed": self.duplicates_suppressed,
            "alerts": serializable,
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        if not quiet:
            print(f"\n{Fore.GREEN}Alerts JSON: {filepath}{Style.RESET_ALL}")
        return filepath

    def get_statistics(self) -> Dict[str, int]:
        return {
            "total_alerts": len(self.alerts),
            "critical": self.alert_counts[config.SEVERITY_CRITICAL],
            "high": self.alert_counts[config.SEVERITY_HIGH],
            "medium": self.alert_counts[config.SEVERITY_MEDIUM],
            "low": self.alert_counts[config.SEVERITY_LOW],
            "info": self.alert_counts[config.SEVERITY_INFO],
            "duplicates_suppressed": self.duplicates_suppressed,
        }
