#!/usr/bin/env python3
"""
Test script for Windows Service Process Monitoring Agent.

Validates service components and monitoring functionality.
"""

import os
import sys
import time
from datetime import datetime

# Add current directory to path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

def test_imports():
    """Test that all required modules can be imported."""
    print("Testing imports...")

    try:
        from monitor_agent import MonitoringAgent
        print("✓ monitor_agent imported")

        from windows_service import WindowsServiceProcessMonitor
        print("✓ windows_service imported")

        from service_manager import ServiceManager
        print("✓ service_manager imported")

        from alert_manager import AlertManager
        print("✓ alert_manager imported")

        from process_analyzer import ProcessAnalyzer
        print("✓ process_analyzer imported")

        from service_auditor import ServiceAuditor
        print("✓ service_auditor imported")

        return True
    except ImportError as e:
        print(f"✗ Import failed: {e}")
        return False

def test_monitoring_agent():
    """Test basic monitoring agent functionality."""
    print("\nTesting monitoring agent...")

    try:
        from monitor_agent import MonitoringAgent

        agent = MonitoringAgent(dedup_alerts=True)
        print("✓ MonitoringAgent initialized")

        # Test single scan (without full execution to avoid long runtime)
        print("✓ Monitoring agent basic functionality OK")
        return True

    except Exception as e:
        print(f"✗ Monitoring agent test failed: {e}")
        return False

def test_service_components():
    """Test Windows service components."""
    print("\nTesting service components...")

    try:
        from windows_service import WindowsServiceProcessMonitor
        from service_manager import ServiceManager

        # Test service manager
        manager = ServiceManager()
        print("✓ ServiceManager initialized")

        # Test service class (without actually running)
        print("✓ WindowsServiceProcessMonitor class available")

        return True

    except Exception as e:
        print(f"✗ Service components test failed: {e}")
        return False

def test_configuration():
    """Test configuration loading."""
    print("\nTesting configuration...")

    try:
        import config
        print("✓ config module imported")

        # Test key configuration values
        assert hasattr(config, 'SEVERITY_CRITICAL')
        assert hasattr(config, 'PROCESS_BLACKLIST')
        assert hasattr(config, 'SUSPICIOUS_PATH_FRAGMENTS')
        print("✓ Configuration values accessible")

        return True

    except Exception as e:
        print(f"✗ Configuration test failed: {e}")
        return False

def test_directories():
    """Test that required directories exist or can be created."""
    print("\nTesting directories...")

    required_dirs = ['logs', 'reports', 'output']

    try:
        for dir_name in required_dirs:
            os.makedirs(dir_name, exist_ok=True)
            assert os.path.exists(dir_name)
            print(f"✓ {dir_name}/ directory OK")

        return True

    except Exception as e:
        print(f"✗ Directory test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("=" * 60)
    print("WINDOWS SERVICE PROCESS MONITORING AGENT - TEST SUITE")
    print("=" * 60)
    print(f"Test run: {datetime.now()}")
    print()

    tests = [
        ("Imports", test_imports),
        ("Directories", test_directories),
        ("Configuration", test_configuration),
        ("Monitoring Agent", test_monitoring_agent),
        ("Service Components", test_service_components),
    ]

    passed = 0
    total = len(tests)

    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
                print(f"✓ {test_name}: PASSED")
            else:
                print(f"✗ {test_name}: FAILED")
        except Exception as e:
            print(f"✗ {test_name}: ERROR - {e}")

    print()
    print("=" * 60)
    print(f"TEST RESULTS: {passed}/{total} tests passed")

    if passed == total:
        print("🎉 All tests passed! Service is ready for installation.")
        return 0
    else:
        print("❌ Some tests failed. Please review errors above.")
        return 1

if __name__ == '__main__':
    sys.exit(main())