"""
Report Generator Module
Generates comprehensive monitoring reports
"""

from datetime import datetime
from typing import List, Dict
import os
import config


class ReportGenerator:
    """Generates detailed monitoring reports"""

    def __init__(self, process_analyzer, service_auditor, alert_manager):
        self.process_analyzer = process_analyzer
        self.service_auditor = service_auditor
        self.alert_manager = alert_manager

    def generate_text_report(self, filename: str = None) -> str:
        """
        Generate a comprehensive text report
        Returns: Path to the generated report file
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"monitoring_report_{timestamp}.txt"

        # Create reports directory if it doesn't exist
        os.makedirs(config.REPORT_DIRECTORY, exist_ok=True)
        filepath = os.path.join(config.REPORT_DIRECTORY, filename)

        with open(filepath, 'w', encoding='utf-8') as f:
            # Header
            f.write("=" * 100 + "\n")
            f.write("WINDOWS SERVICE & PROCESS MONITORING REPORT\n")
            f.write("=" * 100 + "\n")
            f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 100 + "\n\n")

            # Executive Summary
            f.write("EXECUTIVE SUMMARY\n")
            f.write("-" * 100 + "\n")
            stats = self.alert_manager.get_statistics()
            f.write(f"Total Processes Analyzed: {len(self.process_analyzer.processes)}\n")
            f.write(f"Total Services Audited: {len(self.service_auditor.services)}\n")
            f.write(f"Total Alerts Generated: {stats['total_alerts']}\n")
            f.write(f"  - Critical: {stats['critical']}\n")
            f.write(f"  - High: {stats['high']}\n")
            f.write(f"  - Medium: {stats['medium']}\n")
            f.write(f"  - Low: {stats['low']}\n")
            f.write(f"  - Info: {stats['info']}\n\n")

            # Alert Details
            f.write("=" * 100 + "\n")
            f.write("DETAILED ALERTS\n")
            f.write("=" * 100 + "\n\n")

            if not self.alert_manager.alerts:
                f.write("✓ No alerts detected. System appears normal.\n\n")
            else:
                sorted_alerts = self.alert_manager.get_all_alerts()
                for i, alert in enumerate(sorted_alerts, 1):
                    f.write(f"Alert #{i}\n")
                    f.write("-" * 100 + "\n")
                    f.write(f"Type: {alert.get('type', 'N/A')}\n")
                    f.write(f"Severity: {alert.get('severity', 'N/A')}\n")
                    f.write(f"Timestamp: {alert.get('timestamp', 'N/A')}\n")
                    f.write(f"Description: {alert.get('description', 'N/A')}\n")

                    # Print additional details
                    for key, value in alert.items():
                        if key not in ['type', 'severity', 'timestamp', 'description']:
                            f.write(f"{key.replace('_', ' ').title()}: {value}\n")
                    f.write("\n")

            # Process Analysis Section
            f.write("=" * 100 + "\n")
            f.write("PROCESS ANALYSIS\n")
            f.write("=" * 100 + "\n\n")

            # Suspicious relationships
            suspicious_rels = [a for a in self.process_analyzer.anomalies
                              if a.get('type') == 'Suspicious Parent-Child Relationship']
            f.write(f"Suspicious Parent-Child Relationships: {len(suspicious_rels)}\n")
            if suspicious_rels:
                for rel in suspicious_rels:
                    f.write(f"  - {rel.get('parent_name')} (PID {rel.get('parent_pid')}) → "
                           f"{rel.get('child_name')} (PID {rel.get('child_pid')})\n")
            f.write("\n")

            # Unauthorized processes
            unauthorized = [a for a in self.process_analyzer.anomalies
                           if a.get('type') in ['Blacklisted Process Detected',
                                               'Process from Suspicious Location']]
            f.write(f"Unauthorized/Suspicious Processes: {len(unauthorized)}\n")
            if unauthorized:
                for proc in unauthorized:
                    f.write(f"  - {proc.get('process_name')} (PID {proc.get('pid')}) at {proc.get('path')}\n")
            f.write("\n")

            # Service Analysis Section
            f.write("=" * 100 + "\n")
            f.write("SERVICE ANALYSIS\n")
            f.write("=" * 100 + "\n\n")

            # Startup services
            startup_services = self.service_auditor.get_startup_services()
            f.write(f"Auto-Start Services: {len(startup_services)}\n")
            f.write("\n")

            # Suspicious services
            suspicious_services = [a for a in self.service_auditor.anomalies]
            f.write(f"Suspicious Services: {len(suspicious_services)}\n")
            if suspicious_services:
                for svc in suspicious_services:
                    f.write(f"  - {svc.get('service_name')}: {svc.get('description')}\n")
            f.write("\n")

            # Recommendations
            f.write("=" * 100 + "\n")
            f.write("RECOMMENDATIONS\n")
            f.write("=" * 100 + "\n\n")

            if stats['critical'] > 0:
                f.write("⚠ CRITICAL: Immediate action required!\n")
                f.write("  - Investigate all critical alerts immediately\n")
                f.write("  - Isolate affected systems if malware is confirmed\n")
                f.write("  - Run full antivirus/EDR scans\n\n")

            if stats['high'] > 0:
                f.write("⚠ HIGH: Urgent investigation needed\n")
                f.write("  - Review all high-severity alerts\n")
                f.write("  - Check for signs of compromise\n")
                f.write("  - Review authentication logs\n\n")

            if stats['medium'] > 0:
                f.write("⚠ MEDIUM: Further investigation recommended\n")
                f.write("  - Review medium-severity alerts during normal operations\n")
                f.write("  - Verify legitimacy of flagged processes/services\n\n")

            if stats['total_alerts'] == 0:
                f.write("✓ No anomalies detected\n")
                f.write("  - Continue routine monitoring\n")
                f.write("  - Maintain baseline for comparison\n\n")

            # Footer
            f.write("=" * 100 + "\n")
            f.write("END OF REPORT\n")
            f.write("=" * 100 + "\n")

        return filepath

    def generate_summary(self) -> str:
        """Generate a brief summary string"""
        stats = self.alert_manager.get_statistics()
        summary = f"""
Monitoring Summary:
  Processes: {len(self.process_analyzer.processes)}
  Services: {len(self.service_auditor.services)}
  Alerts: {stats['total_alerts']} (Critical: {stats['critical']}, High: {stats['high']}, Medium: {stats['medium']})
"""
        return summary
