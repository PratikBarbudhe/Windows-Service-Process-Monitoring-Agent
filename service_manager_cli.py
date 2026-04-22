"""
Service Control CLI for Windows Service Process Monitoring Agent.

Provides command-line interface for managing the monitoring service:
- Installation with auto-start configuration
- Service start/stop/restart/status
- Registry configuration for automatic startup
- Service removal

Examples:
    python service_manager_cli.py install --auto-start
    python service_manager_cli.py start
    python service_manager_cli.py stop
    python service_manager_cli.py restart
    python service_manager_cli.py status
    python service_manager_cli.py remove
    python service_manager_cli.py set-auto-start
    python service_manager_cli.py set-manual
"""

import argparse
import logging
import os
import sys
import winreg
from typing import Optional

import win32serviceutil
import win32service

# Add current directory to path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from windows_service import WindowsServiceProcessMonitor

logger = logging.getLogger(__name__)

SERVICE_NAME = WindowsServiceProcessMonitor._svc_name_
SERVICE_DISPLAY_NAME = WindowsServiceProcessMonitor._svc_display_name_
REGISTRY_PATH = r"SYSTEM\CurrentControlSet\Services\{0}".format(SERVICE_NAME)


def _setup_logging():
    """Configure logging for service manager."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )


def _is_admin():
    """Check if running with administrator privileges."""
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _check_admin_required():
    """Ensure running as administrator."""
    if not _is_admin():
        print("[ERROR] This operation requires administrator privileges.")
        print("Please run Command Prompt or PowerShell as Administrator and try again.")
        sys.exit(1)


def install(auto_start: bool = False):
    """Install the service."""
    _check_admin_required()
    
    try:
        print(f"[*] Installing {SERVICE_DISPLAY_NAME}...")
        
        # Get the path to the service executable
        service_module_path = os.path.join(current_dir, "windows_service.py")
        
        # Install the service
        win32serviceutil.InstallService(
            pythonClassString="windows_service.WindowsServiceProcessMonitor",
            serviceName=SERVICE_NAME,
            displayName=SERVICE_DISPLAY_NAME,
            exePath=sys.executable,
            params=f'"{service_module_path}"',
        )
        
        print(f"[✓] {SERVICE_DISPLAY_NAME} installed successfully")
        
        if auto_start:
            set_auto_start()
        else:
            print("[*] Service is set to manual startup mode")
            print("    Run: python service_manager_cli.py set-auto-start")
            print("    To enable automatic startup on boot")
        
        return True
        
    except Exception as e:
        print(f"[✗] Failed to install service: {e}")
        logger.error(f"Installation failed: {e}", exc_info=True)
        return False


def set_auto_start():
    """Configure service to start automatically on boot."""
    _check_admin_required()
    
    try:
        print(f"[*] Configuring {SERVICE_NAME} for automatic startup...")
        
        # Open registry
        try:
            reg_key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                REGISTRY_PATH,
                0,
                winreg.KEY_SET_VALUE
            )
        except FileNotFoundError:
            print(f"[✗] Service not found in registry. Install service first.")
            return False
        
        try:
            # Set Start value to 2 (Automatic)
            winreg.SetValueEx(reg_key, "Start", 0, winreg.REG_DWORD, 2)
            print(f"[✓] Service set to automatic startup")
            
            # Also set DelayedAutoStart for stability
            try:
                winreg.SetValueEx(reg_key, "DelayedAutoStart", 0, winreg.REG_DWORD, 1)
                print(f"[✓] Delayed auto-start enabled (30-60 seconds after boot)")
            except Exception as e:
                logger.warning(f"Could not set DelayedAutoStart: {e}")
            
            return True
        finally:
            winreg.CloseKey(reg_key)
            
    except Exception as e:
        print(f"[✗] Failed to configure auto-start: {e}")
        logger.error(f"Auto-start configuration failed: {e}", exc_info=True)
        return False


def set_manual_start():
    """Configure service to start manually."""
    _check_admin_required()
    
    try:
        print(f"[*] Configuring {SERVICE_NAME} for manual startup...")
        
        try:
            reg_key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                REGISTRY_PATH,
                0,
                winreg.KEY_SET_VALUE
            )
        except FileNotFoundError:
            print(f"[✗] Service not found in registry.")
            return False
        
        try:
            # Set Start value to 3 (Manual)
            winreg.SetValueEx(reg_key, "Start", 0, winreg.REG_DWORD, 3)
            print(f"[✓] Service set to manual startup")
            
            # Disable DelayedAutoStart
            try:
                winreg.SetValueEx(reg_key, "DelayedAutoStart", 0, winreg.REG_DWORD, 0)
            except Exception as e:
                logger.warning(f"Could not disable DelayedAutoStart: {e}")
            
            return True
        finally:
            winreg.CloseKey(reg_key)
            
    except Exception as e:
        print(f"[✗] Failed to configure manual start: {e}")
        logger.error(f"Manual start configuration failed: {e}", exc_info=True)
        return False


def start_service():
    """Start the service."""
    _check_admin_required()
    
    try:
        print(f"[*] Starting {SERVICE_DISPLAY_NAME}...")
        win32serviceutil.StartService(SERVICE_NAME)
        print(f"[✓] {SERVICE_DISPLAY_NAME} started successfully")
        return True
    except Exception as e:
        print(f"[✗] Failed to start service: {e}")
        logger.error(f"Start failed: {e}", exc_info=True)
        return False


def stop_service():
    """Stop the service."""
    _check_admin_required()
    
    try:
        print(f"[*] Stopping {SERVICE_DISPLAY_NAME}...")
        win32serviceutil.StopService(SERVICE_NAME)
        print(f"[✓] {SERVICE_DISPLAY_NAME} stopped successfully")
        return True
    except Exception as e:
        print(f"[✗] Failed to stop service: {e}")
        logger.error(f"Stop failed: {e}", exc_info=True)
        return False


def restart_service():
    """Restart the service."""
    _check_admin_required()
    
    try:
        print(f"[*] Restarting {SERVICE_DISPLAY_NAME}...")
        stop_service()
        
        import time
        time.sleep(2)  # Wait for service to stop
        
        start_service()
        return True
    except Exception as e:
        print(f"[✗] Failed to restart service: {e}")
        logger.error(f"Restart failed: {e}", exc_info=True)
        return False


def get_service_status():
    """Get service status."""
    try:
        status = win32serviceutil.QueryServiceStatus(SERVICE_NAME)
        state = status[1]
        
        status_map = {
            win32service.SERVICE_STOPPED: "Stopped",
            win32service.SERVICE_START_PENDING: "Starting",
            win32service.SERVICE_RUNNING: "Running",
            win32service.SERVICE_CONTINUE_PENDING: "Resuming",
            win32service.SERVICE_PAUSE_PENDING: "Pausing",
            win32service.SERVICE_PAUSED: "Paused",
            win32service.SERVICE_STOP_PENDING: "Stopping",
        }
        
        return status_map.get(state, f"Unknown ({state})")
    except Exception as e:
        return "Not installed"


def status():
    """Show service status."""
    try:
        status_text = get_service_status()
        print(f"[*] {SERVICE_DISPLAY_NAME}")
        print(f"    Status: {status_text}")
        
        # Get startup type
        try:
            reg_key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                REGISTRY_PATH,
                0,
                winreg.KEY_READ
            )
            try:
                start_type, _ = winreg.QueryValueEx(reg_key, "Start")
                startup_map = {
                    2: "Automatic",
                    3: "Manual",
                    4: "Disabled",
                }
                print(f"    Startup: {startup_map.get(start_type, f'Unknown ({start_type})')}")
                
                # Check for delayed auto-start
                try:
                    delayed, _ = winreg.QueryValueEx(reg_key, "DelayedAutoStart")
                    if delayed:
                        print(f"    Delayed Auto-start: Enabled")
                except:
                    pass
                    
            finally:
                winreg.CloseKey(reg_key)
        except Exception as e:
            logger.debug(f"Could not read registry: {e}")
        
        return True
    except Exception as e:
        print(f"[✗] Failed to get status: {e}")
        logger.error(f"Status check failed: {e}", exc_info=True)
        return False


def remove_service():
    """Remove the service."""
    _check_admin_required()
    
    try:
        # Stop service first
        current_status = get_service_status()
        if current_status != "Not installed":
            print(f"[*] Stopping service before removal...")
            try:
                stop_service()
                import time
                time.sleep(2)
            except Exception as e:
                logger.warning(f"Could not stop service: {e}")
        
        print(f"[*] Removing {SERVICE_DISPLAY_NAME}...")
        win32serviceutil.RemoveService(SERVICE_NAME)
        print(f"[✓] {SERVICE_DISPLAY_NAME} removed successfully")
        return True
    except Exception as e:
        print(f"[✗] Failed to remove service: {e}")
        logger.error(f"Removal failed: {e}", exc_info=True)
        return False


def main():
    """Main entry point."""
    _setup_logging()
    
    parser = argparse.ArgumentParser(
        description="Service Control for Windows Service Process Monitoring Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python service_manager_cli.py install --auto-start
  python service_manager_cli.py start
  python service_manager_cli.py stop
  python service_manager_cli.py restart
  python service_manager_cli.py status
  python service_manager_cli.py set-auto-start
  python service_manager_cli.py set-manual
  python service_manager_cli.py remove
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Install command
    install_parser = subparsers.add_parser('install', help='Install the service')
    install_parser.add_argument(
        '--auto-start',
        action='store_true',
        help='Configure service to start automatically on boot'
    )
    
    # Start command
    subparsers.add_parser('start', help='Start the service')
    
    # Stop command
    subparsers.add_parser('stop', help='Stop the service')
    
    # Restart command
    subparsers.add_parser('restart', help='Restart the service')
    
    # Status command
    subparsers.add_parser('status', help='Show service status')
    
    # Set auto-start command
    subparsers.add_parser('set-auto-start', help='Configure service for automatic startup')
    
    # Set manual-start command
    subparsers.add_parser('set-manual', help='Configure service for manual startup')
    
    # Remove command
    subparsers.add_parser('remove', help='Remove the service')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 0
    
    # Execute command
    if args.command == 'install':
        success = install(auto_start=args.auto_start)
    elif args.command == 'start':
        success = start_service()
    elif args.command == 'stop':
        success = stop_service()
    elif args.command == 'restart':
        success = restart_service()
    elif args.command == 'status':
        success = status()
    elif args.command == 'set-auto-start':
        success = set_auto_start()
    elif args.command == 'set-manual':
        success = set_manual_start()
    elif args.command == 'remove':
        success = remove_service()
    else:
        parser.print_help()
        success = False
    
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
