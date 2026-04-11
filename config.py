"""
Configuration for the Windows Service & Process Monitoring Agent.

Centralizes detection rules, path heuristics, severity labels, and risk scoring
weights used across process analysis, service auditing, and alerting.
"""

from __future__ import annotations

from typing import Dict, FrozenSet, List, Tuple

# --- Paths ---
REPORT_DIRECTORY = "./reports"
LOG_DIRECTORY = "./logs"

# Directory fragments and patterns (case-insensitive substring match on paths)
SUSPICIOUS_PATH_FRAGMENTS: Tuple[str, ...] = (
    r"C:\Users\Public",
    r"C:\Windows\Temp",
    r"C:\Temp",
    r"\AppData\Local\Temp",
    r"\AppData\Roaming",
    r"\AppData\Local\Microsoft\Windows\INetCache",
    r"\Downloads\",
    r"\Desktop\",
    r"\Startup\",
)

# Writable / user profile areas (persistence and staging)
USER_WRITABLE_PATH_FRAGMENTS: Tuple[str, ...] = (
    r"\Users\",
    r"\AppData\",
    r"\ProgramData\",
)

# Paths considered normal for OS binaries (service path sanity)
SYSTEM_SERVICE_PREFIXES: Tuple[str, ...] = (
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\Windows\",
    r"systemroot\system32",
    r"%systemroot%",
)

# --- Process allow / deny ---
PROCESS_WHITELIST: FrozenSet[str] = frozenset(
    {
        "system",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "services.exe",
        "lsass.exe",
        "svchost.exe",
        "explorer.exe",
        "winlogon.exe",
        "dwm.exe",
        "taskhostw.exe",
        "searchindexer.exe",
        "spoolsv.exe",
        "conhost.exe",
        "fontdrvhost.exe",
        "sihost.exe",
        "ctfmon.exe",
        "runtimebroker.exe",
        "dllhost.exe",
        "audiodg.exe",
        "wudfhost.exe",
        "registry",
        "idle",
        "secure system",
    }
)

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
SINGLETON_PROCESS_NAMES: FrozenSet[str] = frozenset(
    {
        "lsass.exe",
        "winlogon.exe",
        "services.exe",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
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

# Backwards compatibility: older modules used SUSPICIOUS_PATHS
SUSPICIOUS_PATHS: List[str] = list(SUSPICIOUS_PATH_FRAGMENTS)
