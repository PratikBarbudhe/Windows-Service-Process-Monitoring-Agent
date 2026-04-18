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

SEVERITY_ORDER: Dict[str, int] = {
    config.SEVERITY_CRITICAL: 0,
    config.SEVERITY_HIGH: 1,
    config.SEVERITY_MEDIUM: 2,
    config.SEVERITY_LOW: 3,
    config.SEVERITY_INFO: 4,
}

SEVERITY_COLOR_MAP: Dict[str, str] = {
    config.SEVERITY_CRITICAL: Fore.RED,
    config.SEVERITY_HIGH: Fore.LIGHTRED_EX,
    config.SEVERITY_MEDIUM: Fore.YELLOW,
    config.SEVERITY_LOW: Fore.CYAN,
    config.SEVERITY_INFO: Fore.WHITE,
}

FINGERPRINT_FIELDS: Tuple[str, ...] = (
    "type",
    "severity",
    "child_pid",
    "pid",
    "service_name",
    "process_name",
    "path",
    "child_path",
    "description",
)


def _fingerprint(alert: Dict[str, Any]) -> str:
    """Generate stable hash for deduplication across scans."""
    parts: Tuple[Any, ...] = tuple(
        alert.get(field) for field in FINGERPRINT_FIELDS[:-1]
    ) + (alert.get("description"),)
    raw = "|".join(str(p) for p in parts)
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


class AlertManager:
    """Collects alerts, deduplicates, prints colorized summaries, and persists JSON."""

    def __init__(self, dedup: bool = False) -> None:
        self.alerts: List[Dict[str, Any]] = []
        self.dedup_enabled = dedup
        self._seen_fingerprints: Set[str] = set()
        self.duplicates_suppressed = 0
        self.alert_counts: Dict[str, int] = self._new_alert_counts()

    @staticmethod
    def _new_alert_counts() -> Dict[str, int]:
        """Initialize severity counters."""
        return {severity: 0 for severity in SEVERITY_ORDER}

    def clear_session_dedup(self) -> None:
        """Reset deduplication memory (for explicit new sessions)."""
        self._seen_fingerprints.clear()
        self.duplicates_suppressed = 0

    def start_new_scan(self) -> None:
        """Clear scan buffers while optionally retaining dedup fingerprints."""
        self.alerts = []
        self.duplicates_suppressed = 0
        self.alert_counts = self._new_alert_counts()

    def _normalize_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Standardize alert fields for consistency."""
        normalized = ensure_alert_path_field(dict(alert))
        
        # Ensure reason/description are both populated
        if "reason" not in normalized and "description" in normalized:
            normalized["reason"] = normalized["description"]
        if "description" not in normalized and "reason" in normalized:
            normalized["description"] = normalized["reason"]
        
        # Set default risk score if missing
        severity = normalized.get("severity", config.SEVERITY_INFO)
        if "risk_score" not in normalized:
            normalized["risk_score"] = config.RISK_SCORES.get(str(severity), 10)
        
        return normalized

    def add_alert(self, alert: Dict[str, Any]) -> bool:
        """Add a single alert. Returns True if stored, False if suppressed as duplicate."""
        normalized = self._normalize_alert(alert)
        fingerprint = _fingerprint(normalized)
        
        if self.dedup_enabled and fingerprint in self._seen_fingerprints:
            self.duplicates_suppressed += 1
            logger.info("Duplicate alert suppressed: %s", normalized.get("type"))
            return False
        
        if self.dedup_enabled:
            self._seen_fingerprints.add(fingerprint)

        self.alerts.append(normalized)
        severity = str(normalized.get("severity", config.SEVERITY_INFO))
        if severity in self.alert_counts:
            self.alert_counts[severity] += 1
        
        logger.info(
            "Alert [%s] %s — %s",
            severity,
            normalized.get("type"),
            normalized.get("reason") or normalized.get("description", ""),
        )
        return True

    def add_alerts(self, alerts: Iterable[Dict[str, Any]]) -> int:
        """Add multiple alerts; returns count of newly stored alerts."""
        added = 0
        for alert in alerts:
            if self.add_alert(alert):
                added += 1
        return added

    def get_alerts_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        """Filter alerts by severity level."""
        return [a for a in self.alerts if a.get("severity") == severity]

    def get_all_alerts(self) -> List[Dict[str, Any]]:
        """Return all alerts sorted by severity and timestamp."""
        return sorted(
            self.alerts,
            key=lambda x: (
                SEVERITY_ORDER.get(str(x.get("severity", config.SEVERITY_INFO)), 5),
                x.get("timestamp", datetime.now()),
            ),
        )

    def print_alert(self, alert: Dict[str, Any]) -> None:
        """Print a single alert with color and formatting."""
        severity = str(alert.get("severity", config.SEVERITY_INFO))
        color = SEVERITY_COLOR_MAP.get(severity, Fore.WHITE)
        risk_score = alert.get("risk_score", "")

        print(f"\n{color}{'=' * 80}")
        risk_display = f" | risk={risk_score}" if risk_score != "" else ""
        print(f"[{severity}] {alert.get('type', 'Unknown')}{risk_display}")
        print(f"Time: {alert.get('timestamp', 'N/A')}")
        print(f"Reason: {alert.get('reason') or alert.get('description', 'N/A')}")

        # Print additional fields (excluding standard headers)
        standard_fields = {"type", "severity", "timestamp", "description", "reason", "risk_score"}
        for key in sorted(alert.keys()):
            if key not in standard_fields:
                display_key = key.replace("_", " ").title()
                print(f"{display_key}: {alert[key]}")
        
        print(f"{'=' * 80}{Style.RESET_ALL}")

    def print_all_alerts(self) -> None:
        """Print summary and all alerts in color."""
        if not self.alerts:
            print(f"\n{Fore.GREEN}No alerts in this scan window.{Style.RESET_ALL}")
            if self.dedup_enabled and self.duplicates_suppressed:
                print(
                    f"{Fore.CYAN}({self.duplicates_suppressed} duplicate(s) "
                    f"suppressed vs prior scans){Style.RESET_ALL}"
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

    def _serialize_alert_for_export(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Serialize an alert for JSON export (convert datetime to string)."""
        serialized = dict(alert)
        timestamp = serialized.get("timestamp")
        if isinstance(timestamp, datetime):
            serialized["timestamp"] = timestamp.strftime("%Y-%m-%d %H:%M:%S")
        return serialized

    def save_alerts_to_file(self, filename: Optional[str] = None, *, quiet: bool = False) -> str:
        """Save alerts to JSON file with metadata."""
        if filename is None:
            filename = f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        os.makedirs(config.LOG_DIRECTORY, exist_ok=True)
        filepath = os.path.join(config.LOG_DIRECTORY, filename)

        serializable = [self._serialize_alert_for_export(a) for a in self.alerts]
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
        """Return alert statistics summary."""
        return {
            "total_alerts": len(self.alerts),
            "critical": self.alert_counts[config.SEVERITY_CRITICAL],
            "high": self.alert_counts[config.SEVERITY_HIGH],
            "medium": self.alert_counts[config.SEVERITY_MEDIUM],
            "low": self.alert_counts[config.SEVERITY_LOW],
            "info": self.alert_counts[config.SEVERITY_INFO],
            "duplicates_suppressed": self.duplicates_suppressed,
        }
