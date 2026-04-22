"""
Windows Service Process Monitoring Agent — Windows Service Implementation.

This module provides a Windows service wrapper for the monitoring agent,
implementing proper service lifecycle management, logging, and error handling.

Installation:
    python windows_service.py install
    python windows_service.py start

Uninstallation:
    python windows_service.py stop
    python windows_service.py remove

Service Control:
    python windows_service.py status
    python windows_service.py restart
"""

import logging
import os
import sys
import threading
import time
from datetime import datetime
from typing import Optional

import servicemanager
import win32event
import win32service
import win32serviceutil

# Add current directory to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from monitor_agent import MonitoringAgent
from notification_handler import NotificationHandler


class WindowsServiceProcessMonitor(win32serviceutil.ServiceFramework):
    """
    Windows Service implementation for Process Monitoring Agent.

    Provides proper service lifecycle management with start/stop/restart
    capabilities, comprehensive logging, and error handling.
    """

    _svc_name_ = "WindowsServiceProcessMonitor"
    _svc_display_name_ = "Windows Service Process Monitoring Agent"
    _svc_description_ = "Monitors Windows services and processes for security anomalies"

    def __init__(self, args):
        """Initialize the Windows service."""
        win32serviceutil.ServiceFramework.__init__(self, args)

        # Service control
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.is_alive = True

        # Monitoring components
        self.monitoring_agent: Optional[MonitoringAgent] = None
        self.notification_handler: Optional[NotificationHandler] = None
        self.monitoring_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()

        # Service configuration
        self.scan_interval = int(os.environ.get('MONITOR_SCAN_INTERVAL', '60'))
        self.max_retries = int(os.environ.get('MONITOR_MAX_RETRIES', '3'))
        self.retry_delay = int(os.environ.get('MONITOR_RETRY_DELAY', '30'))

        # Setup logging
        self._setup_logging()

    def _setup_logging(self) -> None:
        """Configure comprehensive logging for the service."""
        log_dir = os.path.join(current_dir, 'logs')
        os.makedirs(log_dir, exist_ok=True)

        log_file = os.path.join(log_dir, 'service_monitor.log')
        self.logger = logging.getLogger('WindowsServiceMonitor')
        self.logger.setLevel(logging.INFO)

        # Remove any existing handlers
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)

        # File handler with rotation
        from logging.handlers import RotatingFileHandler
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(logging.INFO)

        # Console handler for debugging
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)

        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

        self.logger.info("Windows Service Process Monitor logging initialized")

    def SvcStop(self) -> None:
        """Handle service stop request."""
        self.logger.info("Service stop requested")
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)

        # Flush any pending batched alerts before stopping
        if self.notification_handler and self.notification_handler._batched_alerts:
            self.logger.info(f"Flushing {len(self.notification_handler._batched_alerts)} pending alerts before stop...")
            self.notification_handler.flush_batched_alerts()

        # Signal monitoring thread to stop
        self.stop_event.set()
        self.is_alive = False

        # Wait for thread to finish (with timeout)
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.logger.info("Waiting for monitoring thread to finish...")
            self.monitoring_thread.join(timeout=30)
            if self.monitoring_thread.is_alive():
                self.logger.warning("Monitoring thread did not stop gracefully")

        # Set stop event
        win32event.SetEvent(self.hWaitStop)
        self.logger.info("Service stopped successfully")

    def SvcDoRun(self) -> None:
        """Main service execution loop."""
        try:
            self.logger.info("Service starting...")
            self.ReportServiceStatus(win32service.SERVICE_START_PENDING)

            # Initialize monitoring agent
            self._initialize_monitoring()

            # Start the monitoring thread
            self.monitoring_thread = threading.Thread(
                target=self._monitoring_loop,
                name="MonitoringThread"
            )
            self.monitoring_thread.daemon = True
            self.monitoring_thread.start()

            self.logger.info(f"Service started successfully. Scan interval: {self.scan_interval}s")
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)

            # Wait for stop event
            win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)

        except Exception as e:
            self.logger.error(f"Critical error in service execution: {e}", exc_info=True)
            self.ReportServiceStatus(win32service.SERVICE_STOPPED)
            raise

    def _initialize_monitoring(self) -> None:
        """Initialize the monitoring agent and notification handler with error handling."""
        try:
            self.logger.info("Initializing monitoring agent...")
            self.monitoring_agent = MonitoringAgent(dedup_alerts=True)
            self.logger.info("Monitoring agent initialized successfully")
            
            # Initialize notification handler
            try:
                self.logger.info("Initializing notification handler...")
                self.notification_handler = NotificationHandler()
                stats = self.notification_handler.get_notification_stats()
                self.logger.info(f"Notification handler initialized: {stats}")
            except Exception as e:
                self.logger.warning(f"Failed to initialize notification handler: {e}")
                self.notification_handler = None
                
        except Exception as e:
            self.logger.error(f"Failed to initialize monitoring agent: {e}", exc_info=True)
            raise

    def _monitoring_loop(self) -> None:
        """Main monitoring loop with error handling and recovery."""
        self.logger.info("Starting monitoring loop")

        consecutive_failures = 0
        scan_count = 0

        while not self.stop_event.is_set():
            try:
                scan_count += 1
                start_time = time.time()

                self.logger.info(f"Starting scan #{scan_count}")

                # Perform monitoring scan
                self._perform_scan()

                # Reset failure counter on success
                consecutive_failures = 0

                # Calculate next scan time
                elapsed = time.time() - start_time
                sleep_time = max(0, self.scan_interval - elapsed)

                self.logger.info(f"Scan #{scan_count} completed in {elapsed:.1f}s. Next scan in {sleep_time:.1f}s")

                # Wait for next scan or stop event
                if not self.stop_event.wait(timeout=sleep_time):
                    continue  # Timeout occurred, do next scan
                else:
                    break  # Stop event was set

            except Exception as e:
                consecutive_failures += 1
                self.logger.error(f"Scan #{scan_count} failed (attempt {consecutive_failures}): {e}", exc_info=True)

                # Implement exponential backoff for retries
                if consecutive_failures < self.max_retries:
                    delay = min(self.retry_delay * (2 ** (consecutive_failures - 1)), 300)  # Max 5 minutes
                    self.logger.info(f"Retrying in {delay} seconds...")
                    if self.stop_event.wait(timeout=delay):
                        break
                else:
                    self.logger.error(f"Too many consecutive failures ({consecutive_failures}). Service may need restart.")
                    # Continue trying but with longer delays
                    if self.stop_event.wait(timeout=self.retry_delay * 2):
                        break

        self.logger.info("Monitoring loop stopped")

    def _perform_scan(self) -> None:
        """Perform a single monitoring scan with comprehensive error handling and notifications."""
        if not self.monitoring_agent:
            raise RuntimeError("Monitoring agent not initialized")

        try:
            # Run the monitoring scan
            self.monitoring_agent.run_single_scan(
                export_csv=True,
                write_scan_json=True
            )

            # Check for alerts and log summary
            alerts = self.monitoring_agent.alert_manager.get_all_alerts()
            if alerts:
                critical_count = sum(1 for a in alerts if a.get('severity') == 'CRITICAL')
                high_count = sum(1 for a in alerts if a.get('severity') == 'HIGH')
                medium_count = sum(1 for a in alerts if a.get('severity') == 'MEDIUM')

                self.logger.info(f"Scan completed: {len(alerts)} alerts "
                               f"(Critical: {critical_count}, High: {high_count}, Medium: {medium_count})")

                # Send notifications for alerts
                if self.notification_handler:
                    notifications_sent = 0
                    for alert in alerts:
                        if self.notification_handler.handle_alert(alert):
                            notifications_sent += 1
                    
                    if notifications_sent > 0:
                        self.logger.info(f"Sent {notifications_sent} notifications")
                
                # Log critical/high alerts
                for alert in alerts:
                    if alert.get('severity') in ['CRITICAL', 'HIGH']:
                        self.logger.warning(f"ALERT {alert.get('severity', '').upper()}: "
                                          f"{alert.get('type', 'Unknown')} - {alert.get('description', '')}")
                
                # Flush batched alerts if needed
                if self.notification_handler and self.notification_handler.should_flush_batch():
                    self.logger.info("Flushing batched email alerts...")
                    flushed = self.notification_handler.flush_batched_alerts()
                    if flushed > 0:
                        self.logger.info(f"Flushed {flushed} batched alerts")
                        
            else:
                self.logger.info("Scan completed: No alerts detected")

        except Exception as e:
            self.logger.error(f"Error during monitoring scan: {e}", exc_info=True)
            raise

    def _check_service_health(self) -> bool:
        """Check service health and resource usage."""
        try:
            # Check if monitoring thread is alive
            if self.monitoring_thread and not self.monitoring_thread.is_alive():
                self.logger.warning("Monitoring thread is not alive")
                return False

            # Check memory usage (basic)
            import psutil
            process = psutil.Process()
            memory_mb = process.memory_info().rss / 1024 / 1024

            if memory_mb > 500:  # 500MB threshold
                self.logger.warning(f"High memory usage detected: {memory_mb:.1f}MB")

            return True

        except Exception as e:
            self.logger.error(f"Error checking service health: {e}")
            return False


def main():
    """Main entry point for service management."""
    if len(sys.argv) == 1:
        # Run as service
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(WindowsServiceProcessMonitor)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        # Handle command line arguments
        win32serviceutil.HandleCommandLine(WindowsServiceProcessMonitor)


if __name__ == '__main__':
    main()