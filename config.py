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

# --- Notification and Alert Configuration ---
# Desktop Notifications
NOTIFICATIONS_ENABLED = os.environ.get("WSPMA_NOTIFICATIONS_ENABLED", "true").lower() == "true"
NOTIFICATION_TOAST_DURATION = 10  # Duration in seconds for desktop notifications

# Minimum severity levels for notifications
NOTIFICATION_SEVERITY_THRESHOLD = os.environ.get("WSPMA_NOTIFICATION_SEVERITY", SEVERITY_HIGH)
DESKTOP_NOTIFICATION_ENABLED = True  # Enable Windows 10 Toast notifications
DESKTOP_NOTIFICATION_ICON = None  # Optional: path to custom icon

# Email Notifications
EMAIL_NOTIFICATIONS_ENABLED = os.environ.get("WSPMA_EMAIL_ENABLED", "false").lower() == "true"
EMAIL_SMTP_SERVER = os.environ.get("WSPMA_SMTP_SERVER", "smtp.gmail.com")
EMAIL_SMTP_PORT = int(os.environ.get("WSPMA_SMTP_PORT", "587"))
EMAIL_SENDER = os.environ.get("WSPMA_EMAIL_SENDER", "")
EMAIL_SENDER_PASSWORD = os.environ.get("WSPMA_EMAIL_PASSWORD", "")
EMAIL_RECIPIENTS = tuple(
    os.environ.get("WSPMA_EMAIL_RECIPIENTS", "").split(",") 
    if os.environ.get("WSPMA_EMAIL_RECIPIENTS", "") else ()
)
EMAIL_USE_TLS = os.environ.get("WSPMA_EMAIL_USE_TLS", "true").lower() == "true"

# Minimum severity levels for email alerts
EMAIL_ALERT_SEVERITY_THRESHOLD = os.environ.get("WSPMA_EMAIL_SEVERITY", SEVERITY_HIGH)
EMAIL_BATCH_ALERTS = os.environ.get("WSPMA_EMAIL_BATCH", "true").lower() == "true"
EMAIL_BATCH_INTERVAL_SECONDS = int(os.environ.get("WSPMA_EMAIL_BATCH_INTERVAL", "300"))

# Alert Trigger Configuration
# System resource thresholds (for triggering alerts)
CPU_THRESHOLD_PERCENT = float(os.environ.get("WSPMA_CPU_THRESHOLD", "80.0"))  # CPU usage threshold
MEMORY_THRESHOLD_PERCENT = float(os.environ.get("WSPMA_MEMORY_THRESHOLD", "85.0"))  # Memory usage threshold
DISK_THRESHOLD_PERCENT = float(os.environ.get("WSPMA_DISK_THRESHOLD", "90.0"))  # Disk usage threshold

# Alert Trigger Types (which alerts trigger notifications)
ALERT_TRIGGER_SUSPICIOUS_PROCESS = os.environ.get("WSPMA_ALERT_SUSPICIOUS_PROCESS", "true").lower() == "true"
ALERT_TRIGGER_SYSTEM_THRESHOLD = os.environ.get("WSPMA_ALERT_SYSTEM_THRESHOLD", "true").lower() == "true"
ALERT_TRIGGER_INJECTION_DETECTED = os.environ.get("WSPMA_ALERT_INJECTION", "true").lower() == "true"
ALERT_TRIGGER_UNUSUAL_SERVICE = os.environ.get("WSPMA_ALERT_UNUSUAL_SERVICE", "true").lower() == "true"

# Notification Rate Limiting (prevent alert storms)
RATE_LIMIT_ENABLED = os.environ.get("WSPMA_RATE_LIMIT", "true").lower() == "true"
RATE_LIMIT_SECONDS = int(os.environ.get("WSPMA_RATE_LIMIT_SECONDS", "60"))  # Minimum seconds between same alert type



# --- Notification and Alert Configuration ---
# Desktop Notifications
NOTIFICATIONS_ENABLED = os.environ.get("WSPMA_NOTIFICATIONS_ENABLED", "true").lower() == "true"
NOTIFICATION_TOAST_DURATION = 10  # Duration in seconds for desktop notifications

# Minimum severity levels for notifications
NOTIFICATION_SEVERITY_THRESHOLD = os.environ.get("WSPMA_NOTIFICATION_SEVERITY", SEVERITY_HIGH)
DESKTOP_NOTIFICATION_ENABLED = True  # Enable Windows 10 Toast notifications
DESKTOP_NOTIFICATION_ICON = None  # Optional: path to custom icon

# Email Notifications
EMAIL_NOTIFICATIONS_ENABLED = os.environ.get("WSPMA_EMAIL_ENABLED", "false").lower() == "true"
EMAIL_SMTP_SERVER = os.environ.get("WSPMA_SMTP_SERVER", "smtp.gmail.com")
EMAIL_SMTP_PORT = int(os.environ.get("WSPMA_SMTP_PORT", "587"))
EMAIL_SENDER = os.environ.get("WSPMA_EMAIL_SENDER", "")
EMAIL_SENDER_PASSWORD = os.environ.get("WSPMA_EMAIL_PASSWORD", "")
EMAIL_RECIPIENTS = tuple(
    os.environ.get("WSPMA_EMAIL_RECIPIENTS", "").split(",") 
    if os.environ.get("WSPMA_EMAIL_RECIPIENTS", "") else ()
)
EMAIL_USE_TLS = os.environ.get("WSPMA_EMAIL_USE_TLS", "true").lower() == "true"

# Minimum severity levels for email alerts
EMAIL_ALERT_SEVERITY_THRESHOLD = os.environ.get("WSPMA_EMAIL_SEVERITY", SEVERITY_HIGH)
EMAIL_BATCH_ALERTS = os.environ.get("WSPMA_EMAIL_BATCH", "true").lower() == "true"
EMAIL_BATCH_INTERVAL_SECONDS = int(os.environ.get("WSPMA_EMAIL_BATCH_INTERVAL", "300"))

# Alert Trigger Configuration
# System resource thresholds (for triggering alerts)
CPU_THRESHOLD_PERCENT = float(os.environ.get("WSPMA_CPU_THRESHOLD", "80.0"))  # CPU usage threshold
MEMORY_THRESHOLD_PERCENT = float(os.environ.get("WSPMA_MEMORY_THRESHOLD", "85.0"))  # Memory usage threshold
DISK_THRESHOLD_PERCENT = float(os.environ.get("WSPMA_DISK_THRESHOLD", "90.0"))  # Disk usage threshold

# Alert Trigger Types (which alerts trigger notifications)
ALERT_TRIGGER_SUSPICIOUS_PROCESS = os.environ.get("WSPMA_ALERT_SUSPICIOUS_PROCESS", "true").lower() == "true"
ALERT_TRIGGER_SYSTEM_THRESHOLD = os.environ.get("WSPMA_ALERT_SYSTEM_THRESHOLD", "true").lower() == "true"
ALERT_TRIGGER_INJECTION_DETECTED = os.environ.get("WSPMA_ALERT_INJECTION", "true").lower() == "true"
ALERT_TRIGGER_UNUSUAL_SERVICE = os.environ.get("WSPMA_ALERT_UNUSUAL_SERVICE", "true").lower() == "true"

# Notification Rate Limiting (prevent alert storms)
RATE_LIMIT_ENABLED = os.environ.get("WSPMA_RATE_LIMIT", "true").lower() == "true"
RATE_LIMIT_SECONDS = int(os.environ.get("WSPMA_RATE_LIMIT_SECONDS", "60"))  # Minimum seconds between same alert type

# --- Process Control Configuration ---
PROCESS_CONTROL_ENABLED = os.environ.get("WSPMA_PROCESS_CONTROL_ENABLED", "false").lower() == "true"
AUTO_KILL_BLACKLISTED = os.environ.get("WSPMA_AUTO_KILL_BLACKLISTED", "false").lower() == "true"
AUTO_BLOCK_SUSPICIOUS = os.environ.get("WSPMA_AUTO_BLOCK_SUSPICIOUS", "false").lower() == "true"
PROCESS_CONTROL_METHOD = os.environ.get("WSPMA_BLOCK_METHOD", "defender")  # defender or applocker

# Process control action configuration
KILL_ON_CRITICAL_ALERT = os.environ.get("WSPMA_KILL_ON_CRITICAL", "false").lower() == "true"
REQUIRE_CONFIRMATION = os.environ.get("WSPMA_REQUIRE_CONFIRMATION", "true").lower() == "true"
