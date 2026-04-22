#!/usr/bin/env python3
"""
Quick setup script for Windows Service Process Monitoring Agent.

This script guides users through the installation and configuration process.

Usage:
    python setup_service.py
"""

import os
import sys
import subprocess
from pathlib import Path

try:
    import ctypes
except ImportError:
    print("[ERROR] ctypes module not found. Please ensure Python is installed correctly.")
    sys.exit(1)


def is_admin():
    """Check if running with administrator privileges."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def prompt_yes_no(question, default=True):
    """Prompt user for yes/no response."""
    default_str = "Y/n" if default else "y/N"
    response = input(f"{question} [{default_str}]: ").strip().lower()
    
    if response == '':
        return default
    return response in ('y', 'yes')


def main():
    """Main setup wizard."""
    
    if not is_admin():
        print("\n[!] This setup wizard requires administrator privileges.")
        print("[!] Please run Command Prompt or PowerShell as Administrator and try again.")
        print("\nTo run as admin:")
        print("  1. Press Windows + X")
        print("  2. Select 'Windows PowerShell (Admin)' or 'Command Prompt (Admin)'")
        print("  3. Run: python setup_service.py")
        sys.exit(1)
    
    print("\n" + "=" * 70)
    print("Windows Service Process Monitoring Agent - Setup Wizard")
    print("=" * 70)
    
    # Check if service_manager_cli.py exists
    script_dir = Path(__file__).parent
    cli_script = script_dir / "service_manager_cli.py"
    
    if not cli_script.exists():
        print("\n[ERROR] service_manager_cli.py not found in current directory.")
        print(f"Please run this script from: {script_dir}")
        sys.exit(1)
    
    # Step 1: Install dependencies
    print("\n[Step 1] Checking dependencies...")
    try:
        import win32serviceutil
        print("[✓] pywin32 is installed")
    except ImportError:
        print("[!] pywin32 is required but not installed")
        if prompt_yes_no("Install now?", default=True):
            subprocess.run([sys.executable, "-m", "pip", "install", "pywin32>=305"], check=True)
            print("[✓] pywin32 installed successfully")
        else:
            print("[ERROR] Cannot proceed without pywin32")
            sys.exit(1)
    
    try:
        import win10toast
        print("[✓] win10toast is installed (desktop notifications)")
    except ImportError:
        print("[!] win10toast not found (desktop notifications will be disabled)")
        if prompt_yes_no("Install win10toast for desktop notifications?", default=True):
            subprocess.run([sys.executable, "-m", "pip", "install", "win10toast>=0.9"], check=True)
            print("[✓] win10toast installed successfully")
    
    # Step 2: Install service
    print("\n[Step 2] Installing Windows Service...")
    
    auto_start = prompt_yes_no(
        "Configure service to start automatically on boot?",
        default=True
    )
    
    try:
        cmd = [sys.executable, str(cli_script), "install"]
        if auto_start:
            cmd.append("--auto-start")
        
        result = subprocess.run(cmd, cwd=script_dir, capture_output=False)
        
        if result.returncode != 0:
            print("\n[ERROR] Service installation failed")
            sys.exit(1)
        
        print("[✓] Service installed successfully")
        
    except Exception as e:
        print(f"\n[ERROR] Failed to install service: {e}")
        sys.exit(1)
    
    # Step 3: Configure notifications (optional)
    print("\n[Step 3] Notification Configuration (Optional)")
    
    if prompt_yes_no("Configure email alerts?", default=False):
        print("\n[Email Configuration]")
        
        print("\nSupported email providers:")
        print("  1. Gmail (recommended)")
        print("  2. Office 365")
        print("  3. Other SMTP (manual configuration)")
        
        provider = input("\nSelect provider (1-3, or press Enter to skip): ").strip()
        
        if provider in ('1', '2', '3'):
            if provider == '1':
                smtp_server = "smtp.gmail.com"
                smtp_port = "587"
                print("\n[Gmail Setup Instructions]")
                print("1. Go to: https://myaccount.google.com/apppasswords")
                print("2. Create an App Password")
                print("3. Use the app password below (16 characters, with spaces)")
            elif provider == '2':
                smtp_server = "smtp.office365.com"
                smtp_port = "587"
                print("\n[Office 365 Setup]")
            else:
                smtp_server = input("SMTP Server: ").strip()
                smtp_port = input("SMTP Port (default 587): ").strip() or "587"
            
            email_sender = input("\nEmail address (sender): ").strip()
            email_password = input("Email password or app password: ").strip()
            email_recipients = input("Recipients (comma-separated): ").strip()
            
            if email_sender and email_password and email_recipients:
                env_vars = {
                    "WSPMA_EMAIL_ENABLED": "true",
                    "WSPMA_EMAIL_SENDER": email_sender,
                    "WSPMA_EMAIL_PASSWORD": email_password,
                    "WSPMA_EMAIL_RECIPIENTS": email_recipients,
                    "WSPMA_SMTP_SERVER": smtp_server,
                    "WSPMA_SMTP_PORT": smtp_port,
                }
                
                try:
                    import winreg
                    for var_name, var_value in env_vars.items():
                        winreg.SetValueEx(
                            winreg.CreateKeyEx(
                                winreg.HKEY_LOCAL_MACHINE,
                                "SYSTEM\\CurrentControlSet\\services\\WindowsServiceProcessMonitor",
                                0,
                                winreg.KEY_SET_VALUE
                            ),
                            var_name,
                            0,
                            winreg.REG_SZ,
                            var_value
                        )
                    print("[✓] Email configuration saved")
                except Exception as e:
                    # Fallback: use environment variables
                    try:
                        for var_name, var_value in env_vars.items():
                            os.environ[var_name] = var_value
                        print("[!] Configuration saved to environment (requires restart to take effect)")
                    except Exception as e2:
                        print(f"[!] Could not save configuration: {e2}")
    
    if prompt_yes_no("Enable desktop notifications?", default=True):
        try:
            os.environ["WSPMA_NOTIFICATIONS_ENABLED"] = "true"
            print("[✓] Desktop notifications enabled")
        except Exception as e:
            print(f"[!] Could not enable desktop notifications: {e}")
    
    # Step 4: Start service
    print("\n[Step 4] Starting Service...")
    
    if prompt_yes_no("Start the service now?", default=True):
        try:
            result = subprocess.run(
                [sys.executable, str(cli_script), "start"],
                cwd=script_dir,
                capture_output=False
            )
            
            if result.returncode == 0:
                print("[✓] Service started successfully")
                
                # Check status
                subprocess.run(
                    [sys.executable, str(cli_script), "status"],
                    cwd=script_dir
                )
            else:
                print("[!] Service may not have started. Check logs at: logs/service_monitor.log")
        except Exception as e:
            print(f"[ERROR] Failed to start service: {e}")
    
    # Summary
    print("\n" + "=" * 70)
    print("Setup Complete!")
    print("=" * 70)
    print("\nNext Steps:")
    print("1. Monitor service: python service_manager_cli.py status")
    print("2. View logs: more logs/service_monitor.log")
    print("3. Restart service: python service_manager_cli.py restart")
    print("4. Stop service: python service_manager_cli.py stop")
    print("\nFor detailed configuration, see: SERVICE_INSTALLATION_GUIDE.md")
    print("=" * 70 + "\n")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Setup cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)
