"""
Alert Manager Module
Handles alert generation, prioritization, and logging
"""

from datetime import datetime
from typing import List, Dict
import os
import json
from colorama import Fore, Style, init
import config

# Initialize colorama for colored console output
init(autoreset=True)


class AlertManager:
    """Manages alerts and provides notification capabilities"""

    def __init__(self):
        self.alerts = []
        self.alert_counts = {
            config.SEVERITY_CRITICAL: 0,
            config.SEVERITY_HIGH: 0,
            config.SEVERITY_MEDIUM: 0,
            config.SEVERITY_LOW: 0,
            config.SEVERITY_INFO: 0
        }

    def add_alert(self, alert: Dict):
        """Add an alert to the alert list"""
        self.alerts.append(alert)
        severity = alert.get('severity', config.SEVERITY_INFO)
        if severity in self.alert_counts:
            self.alert_counts[severity] += 1

    def add_alerts(self, alerts: List[Dict]):
        """Add multiple alerts"""
        for alert in alerts:
            self.add_alert(alert)

    def get_alerts_by_severity(self, severity: str) -> List[Dict]:
        """Get all alerts of a specific severity level"""
        return [alert for alert in self.alerts if alert.get('severity') == severity]

    def get_all_alerts(self) -> List[Dict]:
        """Get all alerts sorted by severity and timestamp"""
        severity_order = {
            config.SEVERITY_CRITICAL: 0,
            config.SEVERITY_HIGH: 1,
            config.SEVERITY_MEDIUM: 2,
            config.SEVERITY_LOW: 3,
            config.SEVERITY_INFO: 4
        }

        return sorted(self.alerts,
                     key=lambda x: (severity_order.get(x.get('severity', config.SEVERITY_INFO), 5),
                                   x.get('timestamp', datetime.now())))

    def print_alert(self, alert: Dict):
        """Print a single alert with color coding"""
        severity = alert.get('severity', config.SEVERITY_INFO)

        # Color mapping
        color_map = {
            config.SEVERITY_CRITICAL: Fore.RED,
            config.SEVERITY_HIGH: Fore.LIGHTRED_EX,
            config.SEVERITY_MEDIUM: Fore.YELLOW,
            config.SEVERITY_LOW: Fore.CYAN,
            config.SEVERITY_INFO: Fore.WHITE
        }

        color = color_map.get(severity, Fore.WHITE)

        print(f"\n{color}{'=' * 80}")
        print(f"[{severity}] {alert.get('type', 'Unknown Alert Type')}")
        print(f"Time: {alert.get('timestamp', 'N/A')}")
        print(f"Description: {alert.get('description', 'No description available')}")

        # Print specific fields based on alert type
        for key, value in alert.items():
            if key not in ['type', 'severity', 'timestamp', 'description']:
                print(f"{key.replace('_', ' ').title()}: {value}")

        print(f"{'=' * 80}{Style.RESET_ALL}")

    def print_all_alerts(self):
        """Print all alerts to console"""
        if not self.alerts:
            print(f"\n{Fore.GREEN}✓ No alerts detected. System appears normal.{Style.RESET_ALL}")
            return

        print(f"\n{Fore.RED}{'=' * 80}")
        print(f"ALERT SUMMARY")
        print(f"{'=' * 80}{Style.RESET_ALL}")
        print(f"Total Alerts: {len(self.alerts)}")
        print(f"  {Fore.RED}Critical: {self.alert_counts[config.SEVERITY_CRITICAL]}{Style.RESET_ALL}")
        print(f"  {Fore.LIGHTRED_EX}High: {self.alert_counts[config.SEVERITY_HIGH]}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}Medium: {self.alert_counts[config.SEVERITY_MEDIUM]}{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}Low: {self.alert_counts[config.SEVERITY_LOW]}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Info: {self.alert_counts[config.SEVERITY_INFO]}{Style.RESET_ALL}")

        sorted_alerts = self.get_all_alerts()
        for alert in sorted_alerts:
            self.print_alert(alert)

    def save_alerts_to_file(self, filename: str = None):
        """Save alerts to JSON file"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"alerts_{timestamp}.json"

        # Create logs directory if it doesn't exist
        os.makedirs(config.LOG_DIRECTORY, exist_ok=True)
        filepath = os.path.join(config.LOG_DIRECTORY, filename)

        # Convert datetime objects to strings for JSON serialization
        serializable_alerts = []
        for alert in self.alerts:
            alert_copy = alert.copy()
            if 'timestamp' in alert_copy and isinstance(alert_copy['timestamp'], datetime):
                alert_copy['timestamp'] = alert_copy['timestamp'].strftime("%Y-%m-%d %H:%M:%S")
            serializable_alerts.append(alert_copy)

        alert_data = {
            'scan_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'total_alerts': len(self.alerts),
            'severity_breakdown': self.alert_counts,
            'alerts': serializable_alerts
        }

        with open(filepath, 'w') as f:
            json.dump(alert_data, f, indent=4)

        print(f"\n{Fore.GREEN}✓ Alerts saved to: {filepath}{Style.RESET_ALL}")
        return filepath

    def get_statistics(self) -> Dict:
        """Get alert statistics"""
        return {
            'total_alerts': len(self.alerts),
            'critical': self.alert_counts[config.SEVERITY_CRITICAL],
            'high': self.alert_counts[config.SEVERITY_HIGH],
            'medium': self.alert_counts[config.SEVERITY_MEDIUM],
            'low': self.alert_counts[config.SEVERITY_LOW],
            'info': self.alert_counts[config.SEVERITY_INFO]
        }
