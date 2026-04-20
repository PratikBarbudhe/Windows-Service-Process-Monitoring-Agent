"""
Configuration for the Windows Service & Process Monitoring Agent.

Centralizes detection rules, path heuristics, severity labels, and risk scoring
weights used across process analysis, service auditing, and alerting.
"""

from __future__ import annotations

import os
from typing import Dict, FrozenSet, Tuple


def _resolve_directory(path: str) -> str:
    return os.path.abspath(os.path.expanduser(os.path.expandvars(path)))

OUTPUT_DIRECTORY = _resolve_directory(os.environ.get("WSPMA_OUTPUT_DIR", "."))
REPORT_DIRECTORY = _resolve_directory(
    os.environ.get("WSPMA_REPORT_DIR", os.path.join(OUTPUT_DIRECTORY, "reports"))
)
LOG_DIRECTORY = _resolve_directory(
    os.environ.get("WSPMA_LOG_DIR", os.path.join(OUTPUT_DIRECTORY, "logs"))
)

# --- Paths ---

# Directory fragments and patterns (case-insensitive substring match on paths)
SUSPICIOUS_PATH_FRAGMENTS: Tuple[str, ...] = (
    "C:\\Users\\Public",
    "C:\\Windows\\Temp",
    "C:\\Temp",
    "\\AppData\\Local\\Temp",
    "\\AppData\\Roaming",
    "\\AppData\\Local\\Microsoft\\Windows\\INetCache",
    "\\Downloads\\",
    "\\Desktop\\",
    "\\Startup\\",
)

# Writable / user profile areas (persistence and staging)
USER_WRITABLE_PATH_FRAGMENTS: Tuple[str, ...] = (
    "\\Users\\",
    "\\AppData\\",
    "\\ProgramData\\",
)

# Paths considered normal for OS binaries (service path sanity)
SYSTEM_SERVICE_PREFIXES: Tuple[str, ...] = (
    "C:\\Windows\\System32",
    "C:\\Windows\\SysWOW64",
    "C:\\Windows\\",
    "systemroot\\system32",
    "%systemroot%",
)

# --- Process detection lists ---
PROCESS_BLACKLIST: FrozenSet[str] = frozenset(
    {
        "mimikatz.exe",
        "psexec.exe",
        "procdump.exe",
        "netcat.exe",
        "nc.exe",
        "pwdump.exe",
        "fgdump.exe",
        "lazagne.exe",
        "rubeus.exe",
        "sharpup.exe",
        "seatbelt.exe",
    }
)

# Processes that should normally appear at most once (possible masquerading if duplicated)
# Only flag names that should almost never appear twice in a healthy session.
SINGLETON_PROCESS_NAMES: FrozenSet[str] = frozenset(
    {
        "lsass.exe",
        "winlogon.exe",
        "services.exe",
    }
)

# --- Parent / child relationships (offensive toolchains often abuse these chains) ---
SUSPICIOUS_RELATIONSHIPS: Dict[str, Tuple[str, ...]] = {
    "winword.exe": ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe"),
    "excel.exe": ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe"),
    "powerpnt.exe": ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"),
    "outlook.exe": ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"),
    "acrord32.exe": ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"),
    "explorer.exe": ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe"),
    "mshta.exe": ("powershell.exe", "cmd.exe", "regsvr32.exe"),
    "wscript.exe": ("powershell.exe", "cmd.exe", "cscript.exe"),
    "cscript.exe": ("powershell.exe", "cmd.exe"),
}

LEGITIMATE_RELATIONSHIPS: Dict[str, Tuple[str, ...]] = {
    "services.exe": ("svchost.exe", "dllhost.exe", "taskhost.exe", "taskhostw.exe", "spoolsv.exe"),
    "svchost.exe": ("dllhost.exe", "taskhostw.exe", "audiodg.exe"),
    "explorer.exe": (
        "chrome.exe",
        "firefox.exe",
        "msedge.exe",
        "notepad.exe",
        "calc.exe",
        "dwm.exe",
        "sihost.exe",
    ),
    "cmd.exe": ("conhost.exe",),
    "powershell.exe": ("conhost.exe",),
}

# --- Command-line heuristics (substring match, lowercased) ---
CMDLINE_SUSPICIOUS_SUBSTRINGS: Tuple[str, ...] = (
    "-encodedcommand",
    "-enc ",
    "bypass",
    "-nop",
    "-noprofile",
    "-windowstyle hidden",
    "-w hidden",
    "invoke-expression",
    "iex(",
    "downloadstring",
    "downloadfile",
    "frombase64string",
    "vssadmin delete shadows",
    "bcdedit",
    "reg save hklm\\sam",
    "comsvcs.dll,#",
)

# --- Services ---
LEGITIMATE_SERVICES: FrozenSet[str] = frozenset(
    {
        "wuauserv",
        "bits",
        "eventlog",
        "schedule",
        "windefend",
        "wsearch",
        "spooler",
        "w32time",
        "lanmanserver",
        "lanmanworkstation",
        "mpssvc",
        "dhcp",
        "dnscache",
        "nsi",
        "nlasvc",
        "rpcss",
        "samss",
        "cryptsvc",
        "dps",
        "diagtrack",
        "themes",
        "audioendpointbuilder",
        "audiosrv",
    }
)

# --- Severity labels ---
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"

# Numeric risk score bucket boundaries (0–100)
RISK_SCORES: Dict[str, int] = {
    SEVERITY_CRITICAL: 90,
    SEVERITY_HIGH: 75,
    SEVERITY_MEDIUM: 50,
    SEVERITY_LOW: 30,
    SEVERITY_INFO: 10,
}

# --- ML and Anomaly Detection Configuration ---
ML_MODEL_CONTAMINATION = 0.1  # Expected proportion of anomalies in training data
ML_MODEL_RANDOM_STATE = 42
CPU_SPIKE_THRESHOLD_SIGMA = 3.0  # Standard deviations above baseline for CPU spike
MEMORY_LEAK_THRESHOLD_SIGMA = 2.0  # Standard deviations for memory leak detection
MIN_BASELINE_SAMPLES = 10  # Minimum samples needed to establish baseline
BEHAVIOR_HISTORY_LENGTH = 100  # Maximum historical measurements to keep per process
METRIC_CLEANUP_AGE_HOURS = 24  # Age threshold for cleaning up old metrics


