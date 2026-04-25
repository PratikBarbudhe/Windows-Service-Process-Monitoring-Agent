#!/usr/bin/env python3
"""
REST API Examples - Demonstrates common API usage patterns

Run examples:
    python api_examples.py login
    python api_examples.py monitor
    python api_examples.py alerts
    python api_examples.py control
    python api_examples.py dashboard
"""

import sys
import json
from datetime import datetime
from api_client import MonitoringAPIClient, APIClientError

# API Server URL
API_URL = "http://localhost:5001"


def print_header(title: str):
    """Print a formatted header."""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def print_success(msg: str):
    """Print success message."""
    print(f"✓ {msg}")


def print_error(msg: str):
    """Print error message."""
    print(f"✗ {msg}")


def example_login():
    """Example: User authentication."""
    print_header("Example 1: User Authentication")
    
    client = MonitoringAPIClient(API_URL)
    
    try:
        # Check API health
        if not client.health_check():
            print_error("API is not available")
            return
        
        print_success("API is healthy")
        
        # Login
        print("\nLogging in...")
        token = client.login("admin", "admin123")
        print_success(f"Login successful")
        print(f"Token (first 40 chars): {token[:40]}...")
        
        # Verify authentication
        if client.verify_auth():
            print_success("Authentication verified")
        
        # Logout
        print("\nLogging out...")
        client.logout()
        print_success("Logout successful")
    
    except APIClientError as e:
        print_error(f"API Error: {e}")


def example_monitor_processes():
    """Example: Monitor processes and detect suspicious activity."""
    print_header("Example 2: Process Monitoring")
    
    client = MonitoringAPIClient(API_URL)
    
    try:
        # Login
        client.login("admin", "admin123")
        
        # Get all processes
        print("\nFetching all processes...")
        processes = client.get_processes(limit=10)
        print(f"Found {len(processes)} processes (showing first 10)")
        
        # Display process list
        print(f"\n{'PID':<8} {'Name':<25} {'Memory (MB)':<12} {'CPU %':<8}")
        print("-" * 55)
        for proc in processes:
            pid = proc.get('pid', 'N/A')
            name = proc.get('name', 'Unknown')[:25]
            memory = proc.get('memory_mb', 0)
            cpu = proc.get('cpu_percent', 0)
            print(f"{pid:<8} {name:<25} {memory:<12.1f} {cpu:<8.1f}")
        
        # Get suspicious processes
        print("\nFetching suspicious processes...")
        suspicious = client.get_processes(include_suspicious=True, limit=5)
        
        if suspicious:
            print(f"Found {len(suspicious)} suspicious processes:")
            for proc in suspicious:
                print(f"  - {proc.get('name', 'Unknown')} (PID: {proc.get('pid')})")
        else:
            print("No suspicious processes detected")
        
        # Get details for a specific process
        if processes:
            first_pid = processes[0]['pid']
            print(f"\nGetting details for PID {first_pid}...")
            details = client.get_process(first_pid)
            proc = details.get('process', {})
            analysis = details.get('analysis', {})
            
            print(f"Process: {proc.get('name')}")
            print(f"Path: {proc.get('path')}")
            print(f"Risk Level: {analysis.get('risk_level', 'Unknown')}")
            if details.get('parent'):
                print(f"Parent: {details['parent'].get('name')} (PID: {details['parent'].get('pid')})")
            if details.get('children'):
                print(f"Children: {len(details['children'])}")
        
        client.logout()
    
    except APIClientError as e:
        print_error(f"API Error: {e}")


def example_monitor_alerts():
    """Example: Monitor and analyze alerts."""
    print_header("Example 3: Alert Monitoring")
    
    client = MonitoringAPIClient(API_URL)
    
    try:
        client.login("admin", "admin123")
        
        # Get recent alerts
        print("\nFetching recent alerts (last 24 hours)...")
        alerts = client.get_alerts(limit=10)
        
        if alerts:
            print(f"Found {len(alerts)} alerts\n")
            
            print(f"{'Severity':<12} {'Type':<25} {'Description':<35}")
            print("-" * 75)
            for alert in alerts:
                severity = alert.get('severity', 'Info')[:12]
                alert_type = alert.get('type', 'Unknown')[:25]
                desc = alert.get('description', '')[:35]
                print(f"{severity:<12} {alert_type:<25} {desc:<35}")
        else:
            print("No alerts found")
        
        # Get critical alerts only
        print("\nFetching critical alerts...")
        critical = client.get_alerts(severity="Critical", limit=5)
        print(f"Found {len(critical)} critical alerts")
        
        for alert in critical:
            print(f"\n  Alert ID: {alert.get('id')}")
            print(f"  Description: {alert.get('description')}")
            print(f"  Time: {alert.get('timestamp')}")
        
        client.logout()
    
    except APIClientError as e:
        print_error(f"API Error: {e}")


def example_process_control():
    """Example: Process control operations."""
    print_header("Example 4: Process Control")
    
    client = MonitoringAPIClient(API_URL)
    
    try:
        client.login("admin", "admin123")
        
        # Get whitelist
        print("\nFetching whitelist...")
        whitelist = client.get_whitelist()
        print(f"Found {len(whitelist)} whitelisted processes")
        
        if whitelist:
            print("\nWhitelisted processes:")
            for entry in whitelist[:5]:
                print(f"  - {entry.get('name')} (Reason: {entry.get('reason')})")
        
        # Get blacklist
        print("\nFetching blacklist...")
        blacklist = client.get_blacklist()
        print(f"Found {len(blacklist)} blacklisted processes")
        
        if blacklist:
            print("\nBlacklisted processes:")
            for entry in blacklist[:5]:
                print(f"  - {entry.get('name')} (Auto-block: {entry.get('auto_block')})")
        
        # Add to whitelist (example)
        print("\n[DEMO] Adding 'example.exe' to whitelist...")
        added = client.add_to_whitelist(
            "example.exe",
            reason="Trusted application for testing"
        )
        if added:
            print_success("Added to whitelist")
        
        # Add to blacklist (example)
        print("\n[DEMO] Adding 'malware_test.exe' to blacklist...")
        added = client.add_to_blacklist(
            "malware_test.exe",
            reason="Test malware pattern",
            auto_block=True
        )
        if added:
            print_success("Added to blacklist")
        
        client.logout()
    
    except APIClientError as e:
        print_error(f"API Error: {e}")


def example_system_dashboard():
    """Example: System monitoring dashboard."""
    print_header("Example 5: System Dashboard")
    
    client = MonitoringAPIClient(API_URL)
    
    try:
        client.login("admin", "admin123")
        
        # Get system statistics
        print("\nFetching system statistics...")
        stats = client.get_stats()
        
        print("\nSystem Statistics:")
        print(f"  Total Processes: {stats.get('total_processes', 0)}")
        print(f"  Total Services: {stats.get('total_services', 0)}")
        print(f"  Alerts (24h): {stats.get('recent_alerts_24h', 0)}")
        print(f"    - Critical: {stats.get('critical_alerts', 0)}")
        print(f"    - High: {stats.get('high_alerts', 0)}")
        
        # Get summary report
        print("\nFetching summary report...")
        report = client.get_summary_report(hours=24)
        
        if report.get('summary'):
            summary = report['summary']
            print("\nReport Summary:")
            print(json.dumps(summary, indent=2))
        
        # Get configuration
        print("\nFetching configuration...")
        config = client.get_config()
        print("\nConfiguration:")
        for key, value in config.get('config', {}).items():
            print(f"  {key}: {value}")
        
        client.logout()
    
    except APIClientError as e:
        print_error(f"API Error: {e}")


def example_threat_response():
    """Example: Threat detection and response workflow."""
    print_header("Example 6: Threat Detection & Response")
    
    client = MonitoringAPIClient(API_URL)
    
    try:
        client.login("admin", "admin123")
        
        # Step 1: Check for alerts
        print("\nStep 1: Checking for recent critical alerts...")
        alerts = client.get_alerts(severity="Critical", limit=5)
        
        if alerts:
            print(f"Found {len(alerts)} critical alerts!")
            
            # Step 2: Analyze the threat
            for alert in alerts:
                alert_id = alert.get('id')
                process_name = alert.get('process_name')
                
                print(f"\nStep 2: Analyzing threat - {process_name}")
                
                # Get process details
                processes = client.get_processes(filter=process_name, limit=1)
                if processes:
                    proc = processes[0]
                    details = client.get_process(proc.get('pid'))
                    analysis = details.get('analysis', {})
                    
                    print(f"  Risk Level: {analysis.get('risk_level')}")
                    print(f"  Indicators: {analysis.get('suspicious_indicators', [])}")
                    
                    # Step 3: Respond to threat
                    print(f"\nStep 3: Responding to threat...")
                    
                    if analysis.get('risk_level') == 'CRITICAL':
                        # Kill the process
                        killed = client.kill_process(
                            proc.get('pid'),
                            force=True,
                            reason=f"Threat response to {alert_id}"
                        )
                        
                        if killed:
                            print_success(f"Terminated malicious process {process_name}")
                            
                            # Add to blacklist
                            client.add_to_blacklist(
                                process_name,
                                reason=f"Threat detected: {alert_id}",
                                auto_block=True
                            )
                            print_success(f"Added {process_name} to auto-block blacklist")
        else:
            print("No critical threats detected")
        
        client.logout()
    
    except APIClientError as e:
        print_error(f"API Error: {e}")


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("REST API Examples\n")
        print("Usage: python api_examples.py <example>")
        print("\nAvailable examples:")
        print("  login      - Authentication example")
        print("  monitor    - Process monitoring example")
        print("  alerts     - Alert monitoring example")
        print("  control    - Process control example")
        print("  dashboard  - System dashboard example")
        print("  threat     - Threat detection & response example")
        print("  all        - Run all examples")
        return
    
    example = sys.argv[1].lower()
    
    if example == 'login' or example == 'all':
        example_login()
    
    if example == 'monitor' or example == 'all':
        example_monitor_processes()
    
    if example == 'alerts' or example == 'all':
        example_monitor_alerts()
    
    if example == 'control' or example == 'all':
        example_process_control()
    
    if example == 'dashboard' or example == 'all':
        example_system_dashboard()
    
    if example == 'threat' or example == 'all':
        example_threat_response()


if __name__ == '__main__':
    main()
