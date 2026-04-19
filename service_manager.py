"""
Service Manager for Windows Service Process Monitoring Agent.

Provides utilities for installing, managing, and monitoring the Windows service.
"""

import argparse
import os
import subprocess
import sys
import time
from typing import Optional

import win32service
import win32serviceutil


class ServiceManager:
    """Manages the Windows Service Process Monitoring Agent."""

    SERVICE_NAME = "WindowsServiceProcessMonitor"
    SERVICE_DISPLAY_NAME = "Windows Service Process Monitoring Agent"

    def __init__(self):
        self.service_name = self.SERVICE_NAME

    def install_service(self, start_type: str = "auto") -> bool:
        """Install the Windows service."""
        try:
            print(f"Installing service: {self.SERVICE_DISPLAY_NAME}")

            # Get the full path to the service script
            script_path = os.path.abspath("windows_service.py")
            python_exe = sys.executable

            # Install the service
            win32serviceutil.InstallService(
                None,  # cls
                self.service_name,
                self.SERVICE_DISPLAY_NAME,
                startType=win32service.SERVICE_AUTO_START if start_type == "auto" else win32service.SERVICE_DEMAND_START,
                exeName=f'"{python_exe}" "{script_path}"',
                description="Monitors Windows services and processes for security anomalies"
            )

            print("✓ Service installed successfully")
            return True

        except Exception as e:
            print(f"✗ Failed to install service: {e}")
            return False

    def uninstall_service(self) -> bool:
        """Uninstall the Windows service."""
        try:
            print(f"Uninstalling service: {self.SERVICE_DISPLAY_NAME}")

            # Stop service if running
            if self.get_service_status() == "running":
                self.stop_service()

            win32serviceutil.RemoveService(self.service_name)
            print("✓ Service uninstalled successfully")
            return True

        except Exception as e:
            print(f"✗ Failed to uninstall service: {e}")
            return False

    def start_service(self) -> bool:
        """Start the Windows service."""
        try:
            print(f"Starting service: {self.SERVICE_DISPLAY_NAME}")
            win32serviceutil.StartService(self.service_name)
            print("✓ Service started successfully")
            return True
        except Exception as e:
            print(f"✗ Failed to start service: {e}")
            return False

    def stop_service(self) -> bool:
        """Stop the Windows service."""
        try:
            print(f"Stopping service: {self.SERVICE_DISPLAY_NAME}")
            win32serviceutil.StopService(self.service_name)
            print("✓ Service stopped successfully")
            return True
        except Exception as e:
            print(f"✗ Failed to stop service: {e}")
            return False

    def restart_service(self) -> bool:
        """Restart the Windows service."""
        print(f"Restarting service: {self.SERVICE_DISPLAY_NAME}")

        if not self.stop_service():
            return False

        # Wait a moment for service to stop
        time.sleep(2)

        if not self.start_service():
            return False

        print("✓ Service restarted successfully")
        return True

    def get_service_status(self) -> str:
        """Get the current status of the service."""
        try:
            status = win32serviceutil.QueryServiceStatus(self.service_name)
            state = status[1]

            status_map = {
                win32service.SERVICE_STOPPED: "stopped",
                win32service.SERVICE_START_PENDING: "starting",
                win32service.SERVICE_STOP_PENDING: "stopping",
                win32service.SERVICE_RUNNING: "running",
                win32service.SERVICE_CONTINUE_PENDING: "continuing",
                win32service.SERVICE_PAUSE_PENDING: "pausing",
                win32service.SERVICE_PAUSED: "paused",
            }

            return status_map.get(state, f"unknown ({state})")

        except Exception as e:
            return f"error: {e}"

    def show_service_info(self) -> None:
        """Display detailed service information."""
        try:
            status = win32serviceutil.QueryServiceStatus(self.service_name)
            print(f"Service Name: {self.service_name}")
            print(f"Display Name: {self.SERVICE_DISPLAY_NAME}")
            print(f"Status: {self.get_service_status()}")
            print(f"Process ID: {status[6] if len(status) > 6 else 'N/A'}")

            # Try to get service configuration
            try:
                config = win32serviceutil.GetServiceCustomOption(self.service_name, "config")
                if config:
                    print(f"Configuration: {config}")
            except:
                pass

        except Exception as e:
            print(f"Error getting service info: {e}")

    def tail_service_logs(self, lines: int = 50) -> None:
        """Tail the service log file."""
        log_file = os.path.join("logs", "service_monitor.log")
        if not os.path.exists(log_file):
            print(f"Log file not found: {log_file}")
            return

        try:
            # Use PowerShell to tail the log file
            cmd = f'Get-Content "{log_file}" -Tail {lines} -Wait'
            print(f"Tailing service logs (last {lines} lines). Press Ctrl+C to stop.")
            subprocess.run(["powershell", "-Command", cmd])
        except KeyboardInterrupt:
            print("\nStopped tailing logs.")
        except Exception as e:
            print(f"Error tailing logs: {e}")


def main():
    """Main CLI for service management."""
    parser = argparse.ArgumentParser(
        description="Windows Service Process Monitoring Agent - Service Manager",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Install command
    install_parser = subparsers.add_parser('install', help='Install the service')
    install_parser.add_argument('--start-type', choices=['auto', 'manual'],
                               default='auto', help='Service start type')

    # Uninstall command
    subparsers.add_parser('uninstall', help='Uninstall the service')

    # Start command
    subparsers.add_parser('start', help='Start the service')

    # Stop command
    subparsers.add_parser('stop', help='Stop the service')

    # Restart command
    subparsers.add_parser('restart', help='Restart the service')

    # Status command
    subparsers.add_parser('status', help='Show service status')

    # Info command
    subparsers.add_parser('info', help='Show detailed service information')

    # Logs command
    logs_parser = subparsers.add_parser('logs', help='Tail service logs')
    logs_parser.add_argument('--lines', type=int, default=50,
                            help='Number of lines to show')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    manager = ServiceManager()

    if args.command == 'install':
        success = manager.install_service(args.start_type)
        if success and args.start_type == 'auto':
            print("Starting service...")
            manager.start_service()

    elif args.command == 'uninstall':
        manager.uninstall_service()

    elif args.command == 'start':
        manager.start_service()

    elif args.command == 'stop':
        manager.stop_service()

    elif args.command == 'restart':
        manager.restart_service()

    elif args.command == 'status':
        status = manager.get_service_status()
        print(f"Service Status: {status}")

    elif args.command == 'info':
        manager.show_service_info()

    elif args.command == 'logs':
        manager.tail_service_logs(args.lines)


if __name__ == '__main__':
    main()