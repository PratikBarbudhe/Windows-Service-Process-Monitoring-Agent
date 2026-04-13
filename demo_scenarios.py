"""
Demonstration alerts for portfolio walkthroughs.

Use ``--simulate`` with ``monitor_agent.py`` to append realistic examples without
running malicious binaries on the host.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List

import config


def get_simulated_alerts() -> List[Dict[str, Any]]:
    """Return synthetic alerts that mirror real detection shapes."""
    ts = datetime.now()
    return [
        {
            "type": "Suspicious Parent-Child Relationship (SIMULATED)",
            "severity": config.SEVERITY_CRITICAL,
            "risk_score": config.RISK_SCORES[config.SEVERITY_CRITICAL],
            "timestamp": ts,
            "parent_name": "winword.exe",
            "parent_pid": 4242,
            "child_name": "powershell.exe",
            "child_pid": 9001,
            "child_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "cmdline": "powershell.exe -NoP -W Hidden -EncodedCommand JAB...",
            "username": "DEMO\\user",
            "reason": "DEMO: Office process spawned PowerShell with encoded payload pattern.",
            "description": "Simulated macro execution / living-off-the-land chain.",
        },
        {
            "type": "Process from Suspicious Location (SIMULATED)",
            "severity": config.SEVERITY_HIGH,
            "risk_score": config.RISK_SCORES[config.SEVERITY_HIGH],
            "timestamp": ts,
            "process_name": "malware_demo.exe",
            "pid": 13131,
            "path": r"C:\Users\Public\malware_demo.exe",
            "cmdline": "malware_demo.exe --persist",
            "username": "DEMO\\user",
            "reason": "DEMO: Binary executed from a world-writable staging directory.",
            "description": "Simulated execution from Users\\Public.",
        },
        {
            "type": "Service from Suspicious Location (SIMULATED)",
            "severity": config.SEVERITY_HIGH,
            "risk_score": config.RISK_SCORES[config.SEVERITY_HIGH],
            "timestamp": ts,
            "service_name": "DemoMalwareService",
            "display_name": "Demo Malware Service (not installed)",
            "path": r"C:\Windows\Temp\svchost_demo.exe",
            "status": "Stopped",
            "start_type": "Auto",
            "reason": "DEMO: Auto-start service binary under Temp (persistence red flag).",
            "description": "Synthetic service record for reporting exercises only.",
        },
    ]
