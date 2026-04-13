"""
Process analysis: enumeration, process tree, and heuristic detections for SOC-style triage.
"""

from __future__ import annotations

import logging
import os
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import psutil

import config

logger = logging.getLogger(__name__)


def _risk_score(severity: str, bump: int = 0) -> int:
    base = config.RISK_SCORES.get(severity, 25)
    return max(0, min(100, base + bump))


def _normalize_cmdline(cmdline: Optional[List[str]]) -> str:
    if not cmdline:
        return ""
    return " ".join(str(p) for p in cmdline)


@dataclass
class ProcessInfo:
    """Normalized snapshot for one process."""

    pid: int
    name: str
    ppid: int
    parent_name: str
    exe_path: str
    cmdline: str
    username: str
    create_time: Optional[datetime]
    cpu_percent: float = 0.0
    memory_rss_bytes: int = 0
    extra: Dict[str, Any] = field(default_factory=dict)


class ProcessAnalyzer:
    """
    Collects process telemetry with psutil and applies detection heuristics.

    Enumerate once, then run individual ``detect_*`` methods to avoid repeated
    iteration over the process list.
    """

    def __init__(self) -> None:
        self.processes: Dict[int, ProcessInfo] = {}
        self.process_tree: Dict[int, List[int]] = {}
        self.anomalies: List[Dict[str, Any]] = []

    def enumerate_processes(self) -> Dict[int, ProcessInfo]:
        """Build ``self.processes`` in a single pass with cached parent names."""
        self.processes = {}
        raw: Dict[int, Dict[str, Any]] = {}

        attrs = ["pid", "name", "ppid", "exe", "cmdline", "username", "create_time", "memory_info"]
        for proc in psutil.process_iter(attrs):
            try:
                info = proc.info
                pid = info.get("pid")
                if pid is None:
                    continue
                raw[pid] = info
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        for pid, pinfo in raw.items():
            try:
                ppid = int(pinfo.get("ppid") or 0)
                parent_name = "N/A"
                if ppid:
                    parent = raw.get(ppid)
                    if parent and parent.get("name"):
                        parent_name = str(parent["name"]).lower()
                    else:
                        try:
                            parent_name = psutil.Process(ppid).name().lower()
                        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                            parent_name = "unknown"

                name_raw = pinfo.get("name") or "unknown"
                exe = (pinfo.get("exe") or "").strip()
                if not exe and pid is not None:
                    try:
                        exe = (psutil.Process(pid).exe() or "").strip()
                    except (psutil.Error, OSError) as ex:
                        logger.debug("exe() unavailable for PID %s: %s", pid, ex)
                        exe = ""
                cmdline_list = pinfo.get("cmdline")
                cmdline = _normalize_cmdline(cmdline_list)
                username = pinfo.get("username") or "N/A"
                ct = pinfo.get("create_time")
                create_time = datetime.fromtimestamp(ct) if ct else None

                mem_info = pinfo.get("memory_info")
                mem_rss = int(mem_info.rss) if mem_info else 0

                self.processes[pid] = ProcessInfo(
                    pid=pid,
                    name=str(name_raw).lower(),
                    ppid=ppid,
                    parent_name=parent_name,
                    exe_path=exe if exe else "N/A",
                    cmdline=cmdline if cmdline else "N/A",
                    username=str(username),
                    create_time=create_time,
                    cpu_percent=0.0,
                    memory_rss_bytes=mem_rss,
                )
            except Exception as exc:  # noqa: BLE001 — best-effort enumeration
                logger.debug("Skipping PID %s: %s", pid, exc)
                continue

        return self.processes

    def build_process_tree(self) -> Dict[int, List[int]]:
        """Map parent PID to child PIDs."""
        self.process_tree = {}
        for pid, proc in self.processes.items():
            ppid = proc.ppid
            if ppid:
                self.process_tree.setdefault(ppid, []).append(pid)
        return self.process_tree

    def detect_suspicious_relationships(self) -> List[Dict[str, Any]]:
        """Office / LOLBAS-style parent-child chains."""
        anomalies: List[Dict[str, Any]] = []
        for pid, proc in self.processes.items():
            parent_name = proc.parent_name
            child_name = proc.name
            suspicious_children = config.SUSPICIOUS_RELATIONSHIPS.get(parent_name, ())
            if child_name not in suspicious_children:
                continue

            legit = config.LEGITIMATE_RELATIONSHIPS.get(parent_name, ())
            if child_name in legit:
                continue

            sev = config.SEVERITY_HIGH
            if parent_name in ("winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe"):
                sev = config.SEVERITY_CRITICAL

            parent_path = "N/A"
            if proc.ppid and proc.ppid in self.processes:
                parent_path = self.processes[proc.ppid].exe_path

            child_path = proc.exe_path if proc.exe_path not in ("", "N/A") else ""
            anomalies.append(
                {
                    "type": "Suspicious Parent-Child Relationship",
                    "severity": sev,
                    "risk_score": _risk_score(sev, 5),
                    "timestamp": datetime.now(),
                    "parent_name": parent_name,
                    "parent_pid": proc.ppid,
                    "parent_path": parent_path,
                    "child_name": child_name,
                    "child_pid": pid,
                    "child_path": child_path or proc.exe_path,
                    "path": child_path or proc.exe_path,
                    "cmdline": proc.cmdline,
                    "username": proc.username,
                    "reason": (
                        f"{parent_name} spawned {child_name}, which is commonly abused for "
                        "code execution or payload staging."
                    ),
                    "description": (
                        f"{parent_name} spawned {child_name} — review command line and network activity."
                    ),
                }
            )
        self.anomalies.extend(anomalies)
        return anomalies

    def detect_unauthorized_processes(self) -> List[Dict[str, Any]]:
        """Blacklist hits and suspicious filesystem locations."""
        unauthorized: List[Dict[str, Any]] = []
        for pid, proc in self.processes.items():
            if proc.name in config.PROCESS_BLACKLIST:
                unauthorized.append(
                    {
                        "type": "Blacklisted Process Detected",
                        "severity": config.SEVERITY_CRITICAL,
                        "risk_score": _risk_score(config.SEVERITY_CRITICAL),
                        "timestamp": datetime.now(),
                        "process_name": proc.name,
                        "pid": pid,
                        "path": proc.exe_path,
                        "cmdline": proc.cmdline,
                        "username": proc.username,
                        "reason": "Process name matches a known offensive-tool indicator list.",
                        "description": f"Blacklisted name: {proc.name}",
                    }
                )
                continue

            exe_lower = proc.exe_path.lower()
            if proc.exe_path != "N/A":
                for fragment in config.SUSPICIOUS_PATH_FRAGMENTS:
                    if fragment.lower() in exe_lower:
                        unauthorized.append(
                            {
                                "type": "Process from Suspicious Location",
                                "severity": config.SEVERITY_MEDIUM,
                                "risk_score": _risk_score(config.SEVERITY_MEDIUM),
                                "timestamp": datetime.now(),
                                "process_name": proc.name,
                                "pid": pid,
                                "path": proc.exe_path,
                                "cmdline": proc.cmdline,
                                "username": proc.username,
                                "reason": f"Binary path contains staging/temp pattern: {fragment}",
                                "description": f"Process running from suspicious location: {proc.exe_path}",
                            }
                        )
                        break

                if not any(a["pid"] == pid for a in unauthorized):
                    for fragment in config.USER_WRITABLE_PATH_FRAGMENTS:
                        if fragment.lower() in exe_lower and "program files" not in exe_lower:
                            unauthorized.append(
                                {
                                    "type": "Process from User-Writable Location",
                                    "severity": config.SEVERITY_LOW,
                                    "risk_score": _risk_score(config.SEVERITY_LOW, 10),
                                    "timestamp": datetime.now(),
                                    "process_name": proc.name,
                                    "pid": pid,
                                    "path": proc.exe_path,
                                    "cmdline": proc.cmdline,
                                    "username": proc.username,
                                    "reason": "Executable resides under a user-writable profile path.",
                                    "description": "Long-running binaries from user profiles warrant validation.",
                                }
                            )
                            break

        self.anomalies.extend(unauthorized)
        return unauthorized

    def detect_suspicious_cmdlines(self) -> List[Dict[str, Any]]:
        """Obfuscated PowerShell, LOLBAS-style invocations."""
        found: List[Dict[str, Any]] = []
        for pid, proc in self.processes.items():
            if proc.cmdline in ("", "N/A"):
                continue
            lower = proc.cmdline.lower()
            hits = [s for s in config.CMDLINE_SUSPICIOUS_SUBSTRINGS if s in lower]
            if not hits:
                continue
            sev = config.SEVERITY_HIGH if any("enc" in h for h in hits) else config.SEVERITY_MEDIUM
            found.append(
                {
                    "type": "Suspicious Command Line",
                    "severity": sev,
                    "risk_score": _risk_score(sev),
                    "timestamp": datetime.now(),
                    "process_name": proc.name,
                    "pid": pid,
                    "path": proc.exe_path,
                    "cmdline": proc.cmdline,
                    "username": proc.username,
                    "matched_patterns": hits,
                    "reason": "Command line matches suspicious substring heuristics.",
                    "description": f"Suspicious patterns in command line: {', '.join(hits[:5])}",
                }
            )
        self.anomalies.extend(found)
        return found

    def detect_process_injection_signs(self) -> List[Dict[str, Any]]:
        """Missing image path (possible hollowing) and image/name mismatch."""
        indicators: List[Dict[str, Any]] = []
        for pid, proc in self.processes.items():
            if proc.exe_path == "N/A" and proc.name not in ("system", "registry", "idle", "secure system"):
                indicators.append(
                    {
                        "type": "Potential Process Injection",
                        "severity": config.SEVERITY_HIGH,
                        "risk_score": _risk_score(config.SEVERITY_HIGH),
                        "timestamp": datetime.now(),
                        "process_name": proc.name,
                        "pid": pid,
                        "path": proc.exe_path,
                        "cmdline": proc.cmdline,
                        "reason": "No valid executable path — may indicate hollowing or access limits.",
                        "description": "Process running without a resolvable executable path.",
                    }
                )

            if proc.exe_path not in ("N/A", ""):
                try:
                    base = os.path.basename(proc.exe_path).lower()
                    img_stem = os.path.splitext(base)[0]
                    proc_stem = os.path.splitext(proc.name)[0]
                    risky_path = any(
                        x in proc.exe_path.lower()
                        for x in ("\\temp\\", "\\tmp\\", "appdata\\local\\temp", "downloads\\")
                    )
                    if base and risky_path and img_stem != proc_stem:
                        indicators.append(
                            {
                                "type": "Image Name Mismatch",
                                "severity": config.SEVERITY_MEDIUM,
                                "risk_score": _risk_score(config.SEVERITY_MEDIUM),
                                "timestamp": datetime.now(),
                                "process_name": proc.name,
                                "pid": pid,
                                "path": proc.exe_path,
                                "cmdline": proc.cmdline,
                                "reason": "Image file name does not match process name under a risky path.",
                                "description": f"Reported name {proc.name} vs on-disk {base}",
                            }
                        )
                except OSError:
                    pass

        self.anomalies.extend(indicators)
        return indicators

    def detect_orphan_processes(self) -> List[Dict[str, Any]]:
        """PPID does not map to a live process (excluding expected kernel parents)."""
        out: List[Dict[str, Any]] = []
        for pid, proc in self.processes.items():
            ppid = proc.ppid
            if ppid in (0, 4) or ppid == pid:
                continue
            if ppid not in self.processes:
                out.append(
                    {
                        "type": "Orphan or Hidden Parent Process",
                        "severity": config.SEVERITY_LOW,
                        "risk_score": _risk_score(config.SEVERITY_LOW, 5),
                        "timestamp": datetime.now(),
                        "process_name": proc.name,
                        "pid": pid,
                        "ppid": ppid,
                        "path": proc.exe_path,
                        "cmdline": proc.cmdline,
                        "reason": "Parent PID is not present in the enumerated snapshot (exited or protected).",
                        "description": f"PPID {ppid} not found for child {proc.name} ({pid}).",
                    }
                )
        self.anomalies.extend(out)
        return out

    def detect_duplicate_names(self) -> List[Dict[str, Any]]:
        """Duplicate sensitive singletons or many copies of the same image name."""
        out: List[Dict[str, Any]] = []
        by_name: Counter[str] = Counter(p.name for p in self.processes.values())

        for name, count in by_name.items():
            if name in config.SINGLETON_PROCESS_NAMES and count > 1:
                pids = [pid for pid, p in self.processes.items() if p.name == name]
                paths_known = [
                    self.processes[x].exe_path
                    for x in pids
                    if x in self.processes and self.processes[x].exe_path not in ("", "N/A")
                ]
                path_field = paths_known[0] if len(paths_known) == 1 else " | ".join(paths_known[:6])
                if len(paths_known) > 6:
                    path_field += " | …"
                out.append(
                    {
                        "type": "Duplicate Critical Process Name",
                        "severity": config.SEVERITY_CRITICAL,
                        "risk_score": _risk_score(config.SEVERITY_CRITICAL),
                        "timestamp": datetime.now(),
                        "process_name": name,
                        "pid": pids[0] if pids else None,
                        "pid_list": pids,
                        "path": path_field or "N/A",
                        "count": count,
                        "reason": "More than one instance of a process that is normally singular.",
                        "description": f"{count} running instances of {name} — possible masquerading.",
                    }
                )

        for name, count in by_name.items():
            if count >= 4 and name not in ("svchost.exe", "dllhost.exe", "conhost.exe"):
                paths = {self.processes[pid].exe_path for pid, p in self.processes.items() if p.name == name}
                if len(paths) >= 3:
                    good_paths = [p for p in paths if p not in ("", "N/A")]
                    path_field = " | ".join(sorted(good_paths)[:6])
                    if len(good_paths) > 6:
                        path_field += " | …"
                    sample_pid = next(
                        (pid for pid, p in self.processes.items() if p.name == name),
                        None,
                    )
                    out.append(
                        {
                            "type": "Duplicate Process Name (Many Paths)",
                            "severity": config.SEVERITY_MEDIUM,
                            "risk_score": _risk_score(config.SEVERITY_MEDIUM),
                            "timestamp": datetime.now(),
                            "process_name": name,
                            "pid": sample_pid,
                            "path": path_field or "N/A",
                            "count": count,
                            "distinct_paths": len(paths),
                            "reason": "Many concurrent processes share the same name from different paths.",
                            "description": f"{count} instances of {name} from {len(paths)} locations.",
                        }
                    )
        self.anomalies.extend(out)
        return out

    def get_process_chain(self, pid: int, max_depth: int = 10) -> List[Tuple[int, str]]:
        """Return ancestry as (pid, name) from root toward the target."""
        chain: List[Tuple[int, str]] = []
        current: Optional[int] = pid
        depth = 0
        seen: set[int] = set()
        while current and depth < max_depth and current not in seen:
            seen.add(current)
            proc = self.processes.get(current)
            if not proc:
                break
            chain.insert(0, (current, proc.name))
            current = proc.ppid if proc.ppid else None
            depth += 1
        return chain

    def get_all_anomalies(self) -> List[Dict[str, Any]]:
        return list(self.anomalies)
