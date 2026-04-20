"""
Windows Service & Process Monitoring Agent — main CLI orchestrator.

Examples:
    python monitor_agent.py
    python monitor_agent.py --continuous --interval 120
    python monitor_agent.py --baseline
    python monitor_agent.py --compare logs/service_baseline_....json
    python monitor_agent.py --process-baseline
    python monitor_agent.py --compare-processes logs/process_baseline_....json
    python monitor_agent.py --train-ml
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

BANNER_WIDTH = 100


def _is_elevated() -> bool:
    """Check if running with administrator privileges (Windows)."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception as e:
        logger.warning(f"Could not check elevation status: {e}")
        return False


def _print_status(message: str, level: str = "info") -> None:
    """Print formatted status message with color and symbol."""
    color_map = {
        "info": Fore.YELLOW,
        "success": Fore.GREEN,
        "action": Fore.CYAN,
        "debug": Fore.MAGENTA,
        "warning": Fore.YELLOW,
        "error": Fore.RED,
    }
    symbol_map = {
        "info": "*",
        "success": "✓",
        "action": "+",
        "debug": "+",
        "warning": "!",
        "error": "✗",
    }
    color = color_map.get(level, Fore.WHITE)
    symbol = symbol_map.get(level, "•")
    print(f"{color}[{symbol}] {message}{Style.RESET_ALL}")

    # Also log to logger
    log_method = getattr(logger, level, logger.info)
    log_method(message)


class MonitoringAgent:
    """Coordinates process analysis, service auditing, alerting, and reporting."""

    def __init__(self, *, dedup_alerts: bool = False) -> None:
        self.alert_manager = AlertManager(dedup=dedup_alerts)
        self.process_analyzer = ProcessAnalyzer()
        self.service_auditor = ServiceAuditor()
        self.report_generator: Optional[ReportGenerator] = None
        self._seen_signatures: Optional[Set[Tuple[str, str]]] = None
        self._scan_count = 0
        self._last_scan_time: Optional[datetime] = None

        logger.info("MonitoringAgent initialized")

    def print_banner(self) -> None:
        """Print agent startup banner."""
        banner = f"""
{Fore.CYAN}{'=' * BANNER_WIDTH}
    WINDOWS SERVICE & PROCESS MONITORING AGENT
    Blue-team oriented telemetry and heuristics
{'=' * BANNER_WIDTH}{Style.RESET_ALL}
"""
        print(banner)
        logger.info("Agent banner displayed")

    def _track_new_process_signatures(self) -> None:
        """Track and alert on new (name, path) process signatures seen during session."""
        current: Set[Tuple[str, str]] = set()
        for proc in self.process_analyzer.processes.values():
            current.add((proc.name.lower(), (proc.exe_path or "").lower()))

        if self._seen_signatures is None:
            self._seen_signatures = set(current)
            return

        fresh = current - self._seen_signatures
        for name, path in sorted(fresh):
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
                    "description": f"New signature observed: {name} @ {path or 'N/A'}",
                }
            )

        self._seen_signatures |= current

    def _run_process_analysis_stage(self) -> None:
        """Execute process enumeration and detection heuristics."""
        _print_status("Enumerating processes (psutil)...", "action")
        processes = self.process_analyzer.enumerate_processes()
        print(f"    Samples: {len(processes)}")

        self._track_new_process_signatures()

        _print_status("Building process tree...", "action")
        tree = self.process_analyzer.build_process_tree()
        print(f"    Parent nodes: {len(tree)}")

        _print_status("Parent / child heuristics...", "action")
        self.alert_manager.add_alerts(self.process_analyzer.detect_suspicious_relationships())

        _print_status("Path / blacklist heuristics...", "action")
        self.alert_manager.add_alerts(self.process_analyzer.detect_unauthorized_processes())

        _print_status("Command-line heuristics...", "action")
        self.alert_manager.add_alerts(self.process_analyzer.detect_suspicious_cmdlines())

        _print_status("Injection / masquerading heuristics...", "action")
        self.alert_manager.add_alerts(self.process_analyzer.detect_process_injection_signs())

        _print_status("Orphan / duplicate heuristics...", "action")
        self.alert_manager.add_alerts(self.process_analyzer.detect_orphan_processes())
        self.alert_manager.add_alerts(self.process_analyzer.detect_duplicate_names())

        _print_status("Behavioral anomaly detection...", "action")
        self.alert_manager.add_alerts(self.process_analyzer.detect_behavioral_anomalies())

        _print_status("Unknown process detection...", "action")
        self.alert_manager.add_alerts(self.process_analyzer.detect_unknown_processes())

    def _run_service_auditing_stage(self, simulate: bool = False) -> None:
        """Execute service enumeration and detection heuristics."""
        _print_status("Enumerating services (WMI / SCM)...", "action")
        services = self.service_auditor.enumerate_services()
        print(f"    Services: {len(services)}")

        _print_status("Auditing service configurations...", "action")
        self.alert_manager.add_alerts(self.service_auditor.detect_suspicious_services())

        if simulate:
            _print_status("Appending simulated demonstration alerts...", "debug")
            self.alert_manager.add_alerts(get_simulated_alerts())

    def _generate_reports_and_exports(
        self,
        export_csv: bool = False,
        write_scan_json: bool = False,
    ) -> Dict[str, Any]:
        """Generate reports and optional exports."""
        _print_status("Writing artifacts...", "info")
        self.report_generator = ReportGenerator(
            self.process_analyzer,
            self.service_auditor,
            self.alert_manager,
        )

        alert_file = self.alert_manager.save_alerts_to_file()
        summary_report = self.report_generator.generate_summary_report()
        detailed_report = self.report_generator.generate_detailed_report()

        exports = []
        if export_csv:
            exports.append(self.report_generator.export_alerts_csv())
        if write_scan_json:
            exports.append(self.report_generator.write_scan_json())

        for path in (summary_report, detailed_report, *exports):
            print(f"{Fore.GREEN}✓ {path}{Style.RESET_ALL}")

        return {
            "alert_file": alert_file,
            "summary_report": summary_report,
            "detailed_report": detailed_report,
            "extra_exports": exports,
            "statistics": self.alert_manager.get_statistics(),
        }

    def run_single_scan(
        self,
        *,
        simulate: bool = False,
        export_csv: bool = False,
        write_scan_json: bool = False,
    ) -> dict:
        """Execute one full monitoring cycle with comprehensive error handling."""
        scan_start = datetime.now()
        self._scan_count += 1

        logger.info(f"Starting scan #{self._scan_count} at {scan_start}")

        try:
            self.alert_manager.start_new_scan()

            # Reinitialize analyzers for each scan to ensure fresh state
            self.process_analyzer = ProcessAnalyzer()
            self.service_auditor = ServiceAuditor()

            _print_status(f"Monitoring scan #{self._scan_count} @ {scan_start:%Y-%m-%d %H:%M:%S}", "info")

            # Process analysis phase
            try:
                self._run_process_analysis_stage()
            except Exception as e:
                logger.error(f"Process analysis failed: {e}", exc_info=True)
                _print_status(f"Process analysis failed: {e}", "error")
                raise

            # Service auditing phase
            try:
                self._run_service_auditing_stage()
            except Exception as e:
                logger.error(f"Service auditing failed: {e}", exc_info=True)
                _print_status(f"Service auditing failed: {e}", "error")
                raise

            # Simulation (if requested)
            if simulate:
                try:
                    _print_status("Appending simulated demonstration alerts...", "debug")
                    self.alert_manager.add_alerts(get_simulated_alerts())
                    logger.info("Simulated alerts added")
                except Exception as e:
                    logger.warning(f"Failed to add simulated alerts: {e}")

            # Reporting phase
            try:
                result = self._generate_reports_and_exports(
                    export_csv=export_csv,
                    write_scan_json=write_scan_json
                )
            except Exception as e:
                logger.error(f"Report generation failed: {e}", exc_info=True)
                _print_status(f"Report generation failed: {e}", "error")
                raise

            scan_duration = (datetime.now() - scan_start).total_seconds()
            logger.info(f"Scan #{self._scan_count} completed successfully in {scan_duration:.1f}s")
            _print_status(f"Scan #{self._scan_count} completed in {scan_duration:.1f}s", "success")

            self._last_scan_time = datetime.now()
            return result

        except Exception as e:
            scan_duration = (datetime.now() - scan_start).total_seconds()
            logger.error(f"Scan #{self._scan_count} failed after {scan_duration:.1f}s: {e}", exc_info=True)
            _print_status(f"Scan #{self._scan_count} failed: {e}", "error")
            raise

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

    def create_process_baseline(self, filename: Optional[str] = None) -> str:
        """Create and save process baseline for ML training and unknown process detection."""
        if filename is None:
            filename = f"process_baseline_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        print(f"\n{Fore.YELLOW}[*] Creating process baseline...{Style.RESET_ALL}")

        # Initialize process analyzer and enumerate
        self.process_analyzer = ProcessAnalyzer()
        processes = self.process_analyzer.enumerate_processes()

        filepath = self.process_analyzer.save_process_baseline(filename)

        print(f"{Fore.GREEN}✓ Process baseline saved: {filepath}{Style.RESET_ALL}")
        print(f"  Processes captured: {len(processes)}")
        return filepath

    def compare_processes_with_baseline(self, baseline_file: str) -> None:
        """Compare current processes against baseline."""
        print(f"\n{Fore.YELLOW}[*] Comparing processes to baseline: {baseline_file}{Style.RESET_ALL}")

        # Load baseline
        if not self.process_analyzer.load_process_baseline(baseline_file):
            print(f"{Fore.RED}[!] Could not load process baseline: {baseline_file}{Style.RESET_ALL}")
            return

        # Enumerate current processes
        self.process_analyzer = ProcessAnalyzer()
        processes = self.process_analyzer.enumerate_processes()

        # Detect unknown processes
        unknown_alerts = self.process_analyzer.detect_unknown_processes()

        print(f"\n{Fore.CYAN}[+] Results{Style.RESET_ALL}")
        print(f"  Current processes: {len(processes)}")
        print(f"  Unknown processes: {len(unknown_alerts)}")

        if unknown_alerts:
            for alert in unknown_alerts:
                print(f"  - {alert.get('process_name')}: {alert.get('path')}")
            self.alert_manager.add_alerts(unknown_alerts)
            self.alert_manager.print_all_alerts()
            self.alert_manager.save_alerts_to_file()
        else:
            print(f"\n{Fore.GREEN}✓ No unknown processes vs baseline{Style.RESET_ALL}")

    def train_ml_model(self) -> bool:
        """Train ML model for anomaly detection."""
        print(f"\n{Fore.YELLOW}[*] Training ML model for anomaly detection...{Style.RESET_ALL}")

        # Initialize process analyzer and collect training data
        self.process_analyzer = ProcessAnalyzer()
        self.process_analyzer.enable_baseline_mode(True)

        # Run multiple scans to collect training data
        print("  Collecting training data over multiple scans...")
        for i in range(5):  # Collect data over 5 scans
            print(f"    Scan {i+1}/5...")
            processes = self.process_analyzer.enumerate_processes()
            self.process_analyzer.behavior_analyzer.collect_training_data()
            time.sleep(2)  # Brief pause between scans

        # Train the model
        success = self.process_analyzer.train_ml_model()

        if success:
            print(f"{Fore.GREEN}✓ ML model trained successfully{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.RED}[!] ML model training failed{Style.RESET_ALL}")
            return False

    def run_continuous_monitoring(
        self,
        interval: int = 60,
        *,
        export_csv: bool = False,
        write_scan_json: bool = False,
        simulate: bool = False,
    ) -> None:
        """Run continuous monitoring with proper error handling and recovery."""
        logger.info(f"Starting continuous monitoring (interval={interval}s)")

        _print_status(f"Continuous monitoring (interval={interval}s, dedup=ON)", "info")
        _print_status("Ctrl+C to stop", "info")

        consecutive_failures = 0
        max_consecutive_failures = 5

        try:
            while True:
                try:
                    # Print scan header
                    print(f"\n{Fore.MAGENTA}{'=' * BANNER_WIDTH}")
                    print(f"SCAN #{self._scan_count + 1} — {datetime.now():%Y-%m-%d %H:%M:%S}")
                    print(f"{'=' * BANNER_WIDTH}{Style.RESET_ALL}\n")

                    # Run the scan
                    self.run_single_scan(
                        simulate=bool(simulate and self._scan_count == 0),  # Only simulate first scan
                        export_csv=export_csv,
                        write_scan_json=write_scan_json,
                    )

                    # Reset failure counter on success
                    consecutive_failures = 0

                    # Sleep until next scan
                    logger.info(f"Sleeping {interval}s until next scan")
                    _print_status(f"Sleeping {interval}s...", "info")
                    time.sleep(interval)

                except Exception as e:
                    consecutive_failures += 1
                    logger.error(f"Scan failed (attempt {consecutive_failures}/{max_consecutive_failures}): {e}")

                    if consecutive_failures >= max_consecutive_failures:
                        logger.error("Too many consecutive failures, stopping continuous monitoring")
                        _print_status("Too many consecutive failures, stopping", "error")
                        break

                    # Exponential backoff for retries
                    retry_delay = min(interval // 4, 30)  # Max 30 seconds
                    logger.info(f"Retrying in {retry_delay} seconds...")
                    _print_status(f"Scan failed, retrying in {retry_delay}s...", "warning")
                    time.sleep(retry_delay)

        except KeyboardInterrupt:
            logger.info(f"Continuous monitoring stopped by user after {self._scan_count} scan(s)")
            _print_status(f"Stopped by user after {self._scan_count} scan(s)", "info")
        except Exception as e:
            logger.error(f"Unexpected error in continuous monitoring: {e}", exc_info=True)
            _print_status(f"Unexpected error: {e}", "error")
            raise


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )


def _normalize_path(path: str) -> str:
    return os.path.abspath(os.path.expanduser(os.path.expandvars(path)))


def _configure_output_directories(
    output_dir: Optional[str], report_dir: Optional[str], log_dir: Optional[str]
) -> None:
    if output_dir:
        base_dir = _normalize_path(output_dir)
        config.REPORT_DIRECTORY = os.path.join(base_dir, "reports")
        config.LOG_DIRECTORY = os.path.join(base_dir, "logs")
    if report_dir:
        config.REPORT_DIRECTORY = _normalize_path(report_dir)
    if log_dir:
        config.LOG_DIRECTORY = _normalize_path(log_dir)

    try:
        os.makedirs(config.REPORT_DIRECTORY, exist_ok=True)
        os.makedirs(config.LOG_DIRECTORY, exist_ok=True)
    except OSError as exc:
        print(f"{Fore.RED}[!] Unable to create output directories: {exc}{Style.RESET_ALL}")
        sys.exit(1)


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Windows Service & Process Monitoring Agent",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--continuous", action="store_true", help="Run repeated scans")
    p.add_argument("--interval", type=int, default=60, help="Seconds between scans")
    p.add_argument("--baseline", action="store_true", help="Write service baseline JSON")
    p.add_argument("--compare", metavar="FILE", help="Compare live services to baseline JSON")
    p.add_argument("--process-baseline", action="store_true", help="Write process baseline JSON for ML training")
    p.add_argument("--compare-processes", metavar="FILE", help="Compare live processes to baseline JSON")
    p.add_argument("--train-ml", action="store_true", help="Train ML model for anomaly detection")
    p.add_argument("--simulate", action="store_true", help="Append demo alerts for walkthroughs")
    p.add_argument("--csv", action="store_true", help="Export alerts CSV under reports/")
    p.add_argument("--scan-json", action="store_true", help="Write combined scan JSON under logs/")
    p.add_argument(
        "--output-dir",
        metavar="DIR",
        help="Base directory for logs and reports (overrides defaults)",
    )
    p.add_argument(
        "--report-dir",
        metavar="DIR",
        help="Output directory for report files (overrides output-dir)",
    )
    p.add_argument(
        "--log-dir",
        metavar="DIR",
        help="Output directory for JSON logs and agent logs (overrides output-dir)",
    )
    p.add_argument("--verbose", action="store_true", help="Verbose logging")
    return p


def main() -> None:
    args = build_arg_parser().parse_args()
    _configure_output_directories(args.output_dir, args.report_dir, args.log_dir)
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
    elif args.process_baseline:
        agent.create_process_baseline()
    elif args.compare_processes:
        agent.compare_processes_with_baseline(args.compare_processes)
    elif args.train_ml:
        agent.train_ml_model()
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
