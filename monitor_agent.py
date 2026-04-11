"""
Windows Service & Process Monitoring Agent
Main entry point for the monitoring system

Usage:
    python monitor_agent.py [options]

Options:
    --continuous    Run continuous monitoring
    --interval N    Set monitoring interval in seconds (default: 60)
    --baseline      Create baseline snapshot of services
    --compare FILE  Compare current state with baseline file
"""

import sys
import os
import time
import argparse
import json
from datetime import datetime
from colorama import Fore, Style, init

# Import monitoring modules
from process_analyzer import ProcessAnalyzer
from service_auditor import ServiceAuditor
from alert_manager import AlertManager
from report_generator import ReportGenerator
import config

# Initialize colorama
init(autoreset=True)


class MonitoringAgent:
    """Main monitoring agent orchestrator"""

    def __init__(self):
        self.process_analyzer = ProcessAnalyzer()
        self.service_auditor = ServiceAuditor()
        self.alert_manager = AlertManager()
        self.report_generator = None

    def print_banner(self):
        """Print application banner"""
        banner = f"""
{Fore.CYAN}{'=' * 100}
    WINDOWS SERVICE & PROCESS MONITORING AGENT
    Defensive Security Tool for Process & Service Analysis
{'=' * 100}{Style.RESET_ALL}
"""
        print(banner)

    def run_single_scan(self):
        """Execute a single monitoring scan"""
        print(f"\n{Fore.YELLOW}[*] Starting monitoring scan...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}\n")

        # Step 1: Enumerate processes
        print(f"{Fore.CYAN}[+] Enumerating active processes...{Style.RESET_ALL}")
        processes = self.process_analyzer.enumerate_processes()
        print(f"    Found {len(processes)} active processes")

        # Step 2: Build process tree
        print(f"{Fore.CYAN}[+] Building process tree...{Style.RESET_ALL}")
        process_tree = self.process_analyzer.build_process_tree()
        print(f"    Mapped {len(process_tree)} parent-child relationships")

        # Step 3: Detect suspicious relationships
        print(f"{Fore.CYAN}[+] Analyzing parent-child relationships...{Style.RESET_ALL}")
        suspicious_rels = self.process_analyzer.detect_suspicious_relationships()
        print(f"    Found {len(suspicious_rels)} suspicious relationships")
        self.alert_manager.add_alerts(suspicious_rels)

        # Step 4: Detect unauthorized processes
        print(f"{Fore.CYAN}[+] Detecting unauthorized processes...{Style.RESET_ALL}")
        unauthorized = self.process_analyzer.detect_unauthorized_processes()
        print(f"    Found {len(unauthorized)} unauthorized processes")
        self.alert_manager.add_alerts(unauthorized)

        # Step 5: Detect process injection signs
        print(f"{Fore.CYAN}[+] Checking for process injection indicators...{Style.RESET_ALL}")
        injection_signs = self.process_analyzer.detect_process_injection_signs()
        print(f"    Found {len(injection_signs)} potential injection indicators")
        self.alert_manager.add_alerts(injection_signs)

        # Step 6: Enumerate services
        print(f"{Fore.CYAN}[+] Enumerating Windows services...{Style.RESET_ALL}")
        services = self.service_auditor.enumerate_services()
        print(f"    Found {len(services)} services")

        # Step 7: Detect suspicious services
        print(f"{Fore.CYAN}[+] Auditing service configurations...{Style.RESET_ALL}")
        suspicious_services = self.service_auditor.detect_suspicious_services()
        print(f"    Found {len(suspicious_services)} suspicious services")
        self.alert_manager.add_alerts(suspicious_services)

        # Step 8: Get startup services
        print(f"{Fore.CYAN}[+] Analyzing startup services...{Style.RESET_ALL}")
        startup_services = self.service_auditor.get_startup_services()
        print(f"    Found {len(startup_services)} auto-start services")

        print(f"\n{Fore.GREEN}[✓] Scan completed!{Style.RESET_ALL}\n")

        # Display alerts
        self.alert_manager.print_all_alerts()

        # Initialize report generator
        self.report_generator = ReportGenerator(
            self.process_analyzer,
            self.service_auditor,
            self.alert_manager
        )

        # Generate reports
        print(f"\n{Fore.YELLOW}[*] Generating reports...{Style.RESET_ALL}")
        alert_file = self.alert_manager.save_alerts_to_file()
        report_file = self.report_generator.generate_text_report()
        print(f"{Fore.GREEN}✓ Report saved to: {report_file}{Style.RESET_ALL}")

        return {
            'alert_file': alert_file,
            'report_file': report_file,
            'statistics': self.alert_manager.get_statistics()
        }

    def create_baseline(self, filename: str = None):
        """Create a baseline snapshot of current services"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"service_baseline_{timestamp}.json"

        print(f"\n{Fore.YELLOW}[*] Creating service baseline...{Style.RESET_ALL}")

        services = self.service_auditor.enumerate_services()

        baseline_data = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'service_count': len(services),
            'services': list(services.keys())
        }

        os.makedirs(config.LOG_DIRECTORY, exist_ok=True)
        filepath = os.path.join(config.LOG_DIRECTORY, filename)

        with open(filepath, 'w') as f:
            json.dump(baseline_data, f, indent=4)

        print(f"{Fore.GREEN}✓ Baseline created: {filepath}{Style.RESET_ALL}")
        print(f"  Services captured: {len(services)}")

        return filepath

    def compare_with_baseline(self, baseline_file: str):
        """Compare current services with a baseline"""
        print(f"\n{Fore.YELLOW}[*] Comparing with baseline: {baseline_file}{Style.RESET_ALL}")

        try:
            with open(baseline_file, 'r') as f:
                baseline_data = json.load(f)

            baseline_services = set(baseline_data['services'])
            baseline_time = baseline_data['timestamp']

            print(f"  Baseline timestamp: {baseline_time}")
            print(f"  Baseline services: {len(baseline_services)}")

            # Enumerate current services
            current_services = self.service_auditor.enumerate_services()

            # Detect new services
            new_services = self.service_auditor.detect_new_services(baseline_services)

            print(f"\n{Fore.CYAN}[+] Comparison Results:{Style.RESET_ALL}")
            print(f"  Current services: {len(current_services)}")
            print(f"  New services: {len(new_services)}")

            if new_services:
                print(f"\n{Fore.YELLOW}New services detected:{Style.RESET_ALL}")
                for svc in new_services:
                    print(f"  - {svc.get('service_name')}: {svc.get('display_name')}")

                self.alert_manager.add_alerts(new_services)
            else:
                print(f"\n{Fore.GREEN}✓ No new services detected{Style.RESET_ALL}")

        except FileNotFoundError:
            print(f"{Fore.RED}[!] Baseline file not found: {baseline_file}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error comparing baseline: {e}{Style.RESET_ALL}")

    def run_continuous_monitoring(self, interval: int = 60):
        """Run continuous monitoring with specified interval"""
        print(f"\n{Fore.YELLOW}[*] Starting continuous monitoring (interval: {interval}s){Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Press Ctrl+C to stop{Style.RESET_ALL}\n")

        scan_count = 0

        try:
            while True:
                scan_count += 1
                print(f"\n{Fore.MAGENTA}{'=' * 100}")
                print(f"SCAN #{scan_count} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"{'=' * 100}{Style.RESET_ALL}\n")

                # Reset alerts for new scan
                self.alert_manager = AlertManager()
                self.process_analyzer = ProcessAnalyzer()
                self.service_auditor = ServiceAuditor()

                # Run scan
                self.run_single_scan()

                # Wait for next scan
                print(f"\n{Fore.CYAN}[*] Next scan in {interval} seconds...{Style.RESET_ALL}")
                time.sleep(interval)

        except KeyboardInterrupt:
            print(f"\n\n{Fore.YELLOW}[*] Monitoring stopped by user{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[✓] Total scans completed: {scan_count}{Style.RESET_ALL}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Windows Service & Process Monitoring Agent',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('--continuous', action='store_true',
                       help='Run continuous monitoring')
    parser.add_argument('--interval', type=int, default=60,
                       help='Monitoring interval in seconds (default: 60)')
    parser.add_argument('--baseline', action='store_true',
                       help='Create baseline snapshot of services')
    parser.add_argument('--compare', type=str, metavar='FILE',
                       help='Compare current state with baseline file')

    args = parser.parse_args()

    # Create monitoring agent
    agent = MonitoringAgent()
    agent.print_banner()

    # Check if running with admin privileges (recommended)
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if not is_admin:
            print(f"{Fore.YELLOW}[!] Warning: Not running with administrator privileges{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Some monitoring features may be limited{Style.RESET_ALL}\n")
    except:
        pass

    # Execute based on arguments
    if args.baseline:
        agent.create_baseline()
    elif args.compare:
        agent.compare_with_baseline(args.compare)
    elif args.continuous:
        agent.run_continuous_monitoring(args.interval)
    else:
        # Run single scan
        agent.run_single_scan()

    print(f"\n{Fore.GREEN}{'=' * 100}")
    print(f"Monitoring session completed")
    print(f"{'=' * 100}{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()
