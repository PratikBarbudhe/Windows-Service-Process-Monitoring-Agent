"""
Windows Service & Process Monitoring Agent — main CLI orchestrator.

Examples:
    python monitor_agent.py
    python monitor_agent.py --continuous --interval 120
    python monitor_agent.py --baseline
    python monitor_agent.py --compare logs/service_baseline_....json
    python monitor_agent.py --simulate --csv
    streamlit run dashboard_streamlit.py
"""

from __future__ import annotations

import argparse
import ctypes
import json
import logging
import os
import sys
import time
from datetime import datetime
from typing import Optional, Set, Tuple

from colorama import Fore, Style, init

import config
from alert_manager import AlertManager
from demo_scenarios import get_simulated_alerts
from process_analyzer import ProcessAnalyzer
from report_generator import ReportGenerator
from service_auditor import ServiceAuditor, baseline_names_from_file, build_baseline_payload

init(autoreset=True)

logger = logging.getLogger(__name__)


def _is_elevated() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


class MonitoringAgent:
    """Coordinates process analysis, service auditing, alerting, and reporting."""

    def __init__(self, *, dedup_alerts: bool = False) -> None:
        self.alert_manager = AlertManager(dedup=dedup_alerts)
        self.process_analyzer = ProcessAnalyzer()
        self.service_auditor = ServiceAuditor()
        self.report_generator: Optional[ReportGenerator] = None
        self._seen_signatures: Optional[Set[Tuple[str, str]]] = None

    def print_banner(self) -> None:
        banner = f"""
{Fore.CYAN}{'=' * 100}
    WINDOWS SERVICE & PROCESS MONITORING AGENT
    Blue-team oriented telemetry and heuristics
{'=' * 100}{Style.RESET_ALL}
"""
        print(banner)

    def _detect_new_process_signatures(self) -> None:
        """
        Emit informational alerts when a (name, image path) pair appears for the first time
        in this agent session. Reduces PID churn noise while still surfacing new binaries.
        """
        current: Set[Tuple[str, str]] = set()
        for proc in self.process_analyzer.processes.values():
            current.add((proc.name.lower(), (proc.exe_path or "").lower()))

        if self._seen_signatures is None:
            self._seen_signatures = set(current)
            return

        fresh = current - self._seen_signatures
        for name, path in sorted(fresh):
            desc = f"New signature observed: {name} @ {path or 'N/A'}"
            pid_match = next(
                (
                    pid
                    for pid, p in self.process_analyzer.processes.items()
                    if p.name.lower() == name and (p.exe_path or "").lower() == path
                ),
                None,
            )
            self.alert_manager.add_alert(
                {
                    "type": "New Process Signature",
                    "severity": config.SEVERITY_INFO,
                    "risk_score": config.RISK_SCORES[config.SEVERITY_INFO],
                    "timestamp": datetime.now(),
                    "process_name": name,
                    "pid": pid_match,
                    "path": path or "N/A",
                    "reason": "First observation of this name/path pair during this session.",
                    "description": desc,
                }
            )

        self._seen_signatures |= current

    def run_single_scan(
        self,
        *,
        simulate: bool = False,
        export_csv: bool = False,
        write_scan_json: bool = False,
    ) -> dict:
        """Execute one full monitoring cycle."""
        self.alert_manager.start_new_scan()

        self.process_analyzer = ProcessAnalyzer()
        self.service_auditor = ServiceAuditor()

        print(f"\n{Fore.YELLOW}[*] Monitoring scan @ {datetime.now():%Y-%m-%d %H:%M:%S}{Style.RESET_ALL}\n")

        print(f"{Fore.CYAN}[+] Enumerating processes (psutil)...{Style.RESET_ALL}")
        processes = self.process_analyzer.enumerate_processes()
        print(f"    Samples: {len(processes)}")

        self._detect_new_process_signatures()

        print(f"{Fore.CYAN}[+] Building process tree...{Style.RESET_ALL}")
        tree = self.process_analyzer.build_process_tree()
        print(f"    Parent nodes: {len(tree)}")

        print(f"{Fore.CYAN}[+] Parent / child heuristics...{Style.RESET_ALL}")
        self.alert_manager.add_alerts(self.process_analyzer.detect_suspicious_relationships())

        print(f"{Fore.CYAN}[+] Path / blacklist heuristics...{Style.RESET_ALL}")
        self.alert_manager.add_alerts(self.process_analyzer.detect_unauthorized_processes())

        print(f"{Fore.CYAN}[+] Command-line heuristics...{Style.RESET_ALL}")
        self.alert_manager.add_alerts(self.process_analyzer.detect_suspicious_cmdlines())

        print(f"{Fore.CYAN}[+] Injection / masquerading heuristics...{Style.RESET_ALL}")
        self.alert_manager.add_alerts(self.process_analyzer.detect_process_injection_signs())

        print(f"{Fore.CYAN}[+] Orphan / duplicate heuristics...{Style.RESET_ALL}")
        self.alert_manager.add_alerts(self.process_analyzer.detect_orphan_processes())
        self.alert_manager.add_alerts(self.process_analyzer.detect_duplicate_names())

        print(f"{Fore.CYAN}[+] Enumerating services (WMI / SCM)...{Style.RESET_ALL}")
        services = self.service_auditor.enumerate_services()
        print(f"    Services: {len(services)}")

        print(f"{Fore.CYAN}[+] Auditing service configurations...{Style.RESET_ALL}")
        self.alert_manager.add_alerts(self.service_auditor.detect_suspicious_services())

        if simulate:
            print(f"{Fore.MAGENTA}[+] Appending simulated demonstration alerts...{Style.RESET_ALL}")
            self.alert_manager.add_alerts(get_simulated_alerts())

        print(f"\n{Fore.GREEN}[✓] Scan stage complete{Style.RESET_ALL}\n")
        self.alert_manager.print_all_alerts()

        self.report_generator = ReportGenerator(
            self.process_analyzer,
            self.service_auditor,
            self.alert_manager,
        )

        print(f"{Fore.YELLOW}[*] Writing artifacts...{Style.RESET_ALL}")
        alert_path = self.alert_manager.save_alerts_to_file()
        summary_path = self.report_generator.generate_summary_report()
        detailed_path = self.report_generator.generate_detailed_report()

        extras = []
        if export_csv:
            extras.append(self.report_generator.export_alerts_csv())
        if write_scan_json:
            extras.append(self.report_generator.write_scan_json())

        for p in (summary_path, detailed_path, *extras):
            print(f"{Fore.GREEN}✓ {p}{Style.RESET_ALL}")

        return {
            "alert_file": alert_path,
            "summary_report": summary_path,
            "detailed_report": detailed_path,
            "extra_exports": extras,
            "statistics": self.alert_manager.get_statistics(),
        }

    def create_baseline(self, filename: Optional[str] = None) -> str:
        if filename is None:
            filename = f"service_baseline_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        print(f"\n{Fore.YELLOW}[*] Creating service baseline...{Style.RESET_ALL}")
        self.service_auditor = ServiceAuditor()
        services = self.service_auditor.enumerate_services()
        payload = build_baseline_payload(services)

        os.makedirs(config.LOG_DIRECTORY, exist_ok=True)
        filepath = os.path.join(config.LOG_DIRECTORY, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        print(f"{Fore.GREEN}✓ Baseline saved: {filepath}{Style.RESET_ALL}")
        print(f"  Services captured: {payload['service_count']}")
        return filepath

    def compare_with_baseline(self, baseline_file: str) -> None:
        print(f"\n{Fore.YELLOW}[*] Comparing services to baseline: {baseline_file}{Style.RESET_ALL}")
        try:
            with open(baseline_file, encoding="utf-8") as f:
                baseline_data = json.load(f)
        except FileNotFoundError:
            print(f"{Fore.RED}[!] Baseline not found: {baseline_file}{Style.RESET_ALL}")
            return
        except json.JSONDecodeError as exc:
            print(f"{Fore.RED}[!] Invalid JSON: {exc}{Style.RESET_ALL}")
            return

        names = baseline_names_from_file(baseline_data)
        print(f"  Baseline timestamp: {baseline_data.get('timestamp', 'unknown')}")
        print(f"  Baseline service names: {len(names)}")

        self.service_auditor = ServiceAuditor()
        current = self.service_auditor.enumerate_services()
        new_services = self.service_auditor.detect_new_services(names)

        print(f"\n{Fore.CYAN}[+] Results{Style.RESET_ALL}")
        print(f"  Current services: {len(current)}")
        print(f"  New vs baseline: {len(new_services)}")

        if new_services:
            for svc in new_services:
                print(f"  - {svc.get('service_name')}: {svc.get('display_name')}")
            self.alert_manager.add_alerts(new_services)
            self.alert_manager.print_all_alerts()
            self.alert_manager.save_alerts_to_file()
        else:
            print(f"\n{Fore.GREEN}✓ No new services vs baseline{Style.RESET_ALL}")

    def run_continuous_monitoring(
        self,
        interval: int = 60,
        *,
        export_csv: bool = False,
        write_scan_json: bool = False,
        simulate: bool = False,
    ) -> None:
        print(
            f"\n{Fore.YELLOW}[*] Continuous monitoring (interval={interval}s, dedup=ON){Style.RESET_ALL}"
        )
        print(f"{Fore.YELLOW}[*] Ctrl+C to stop{Style.RESET_ALL}\n")

        scan_count = 0

        try:
            while True:
                scan_count += 1
                print(f"\n{Fore.MAGENTA}{'=' * 100}")
                print(f"SCAN #{scan_count} — {datetime.now():%Y-%m-%d %H:%M:%S}")
                print(f"{'=' * 100}{Style.RESET_ALL}\n")

                self.run_single_scan(
                    simulate=bool(simulate and scan_count == 1),
                    export_csv=export_csv,
                    write_scan_json=write_scan_json,
                )

                print(f"\n{Fore.CYAN}[*] Sleeping {interval}s...{Style.RESET_ALL}")
                time.sleep(interval)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[*] Stopped by user after {scan_count} scan(s){Style.RESET_ALL}")


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Windows Service & Process Monitoring Agent",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--continuous", action="store_true", help="Run repeated scans")
    p.add_argument("--interval", type=int, default=60, help="Seconds between scans")
    p.add_argument("--baseline", action="store_true", help="Write service baseline JSON")
    p.add_argument("--compare", metavar="FILE", help="Compare live services to baseline JSON")
    p.add_argument("--simulate", action="store_true", help="Append demo alerts for walkthroughs")
    p.add_argument("--csv", action="store_true", help="Export alerts CSV under reports/")
    p.add_argument("--scan-json", action="store_true", help="Write combined scan JSON under logs/")
    p.add_argument("--verbose", action="store_true", help="Verbose logging")
    return p


def main() -> None:
    args = build_arg_parser().parse_args()
    _configure_logging(args.verbose)

    agent = MonitoringAgent(dedup_alerts=False)
    agent.print_banner()

    if not _is_elevated():
        print(
            f"{Fore.YELLOW}[!] Not elevated — some handles/paths may be incomplete.{Style.RESET_ALL}\n"
        )

    if args.baseline:
        agent.create_baseline()
    elif args.compare:
        agent.compare_with_baseline(args.compare)
    elif args.continuous:
        MonitoringAgent(dedup_alerts=True).run_continuous_monitoring(
            args.interval,
            export_csv=args.csv,
            write_scan_json=args.scan_json,
            simulate=args.simulate,
        )
    else:
        agent.run_single_scan(
            simulate=args.simulate,
            export_csv=args.csv,
            write_scan_json=args.scan_json,
        )

    print(f"\n{Fore.GREEN}{'=' * 100}\nSession complete\n{'=' * 100}{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()
