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
from anomaly_detector import BehaviorAnalyzer

logger = logging.getLogger(__name__)

COMMON_SAFE_PROCESSES = {"system", "registry", "idle", "secure system"}
COMMON_MULTI_INSTANCE_WHITELIST = {"svchost.exe", "dllhost.exe", "conhost.exe"}
TEMP_PATH_INDICATORS = (
    "\\temp\\",
    "\\tmp\\",
    "appdata\\local\\temp",
    "downloads\\",
)

COMMON_SAFE_PROCESSES = {"system", "registry", "idle", "secure system"}
COMMON_MULTI_INSTANCE_WHITELIST = {"svchost.exe", "dllhost.exe", "conhost.exe"}
TEMP_PATH_INDICATORS = (
    "\\temp\\",
    "\\tmp\\",
    "appdata\\local\\temp",
    "downloads\\",
)


def _risk_score(severity: str, bump: int = 0) -> int:
    return max(0, min(100, config.RISK_SCORES.get(severity, 25) + bump))


def _normalize_cmdline(cmdline: Optional[List[str]]) -> str:
    if not cmdline:
        return ""
    return " ".join(str(part) for part in cmdline)


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
        self.behavior_analyzer = BehaviorAnalyzer()

    def enumerate_processes(self) -> Dict[int, ProcessInfo]:
        """Build ``self.processes`` in a single pass with cached parent names."""
        self.processes = {}
        raw: Dict[int, Dict[str, Any]] = {}

        attrs = [
            "pid",
            "name",
            "ppid",
            "exe",
            "cmdline",
            "username",
            "create_time",
            "memory_info",
            "cpu_percent",
            "num_threads",
        ]
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
                proc_info = self._build_process_info(pid, pinfo, raw)
                self.processes[pid] = proc_info

                # Update behavior analyzer with current metrics
                cpu_percent = float(pinfo.get("cpu_percent") or 0.0)
                thread_count = int(pinfo.get("num_threads") or 0)
                memory_rss = proc_info.memory_rss_bytes

                self.behavior_analyzer.update_process_metrics(
                    pid, proc_info.name, cpu_percent, memory_rss, thread_count
                )

            except Exception as exc:  # noqa: BLE001 — best-effort enumeration
                logger.debug("Skipping PID %s: %s", pid, exc)

        return self.processes

    def _build_process_info(
        self,
        pid: int,
        pinfo: Dict[str, Any],
        raw: Dict[int, Dict[str, Any]],
    ) -> ProcessInfo:
        ppid = int(pinfo.get("ppid") or 0)
        parent_name = self._resolve_parent_name(ppid, raw)

        exe = (pinfo.get("exe") or "").strip() or self._safe_exe_path(pid)
        cmdline = _normalize_cmdline(pinfo.get("cmdline")) or "N/A"
        username = pinfo.get("username") or "N/A"
        create_time = self._parse_create_time(pinfo.get("create_time"))
        mem_info = pinfo.get("memory_info")
        mem_rss = int(mem_info.rss) if mem_info else 0

        return ProcessInfo(
            pid=pid,
            name=str(pinfo.get("name") or "unknown").lower(),
            ppid=ppid,
            parent_name=parent_name,
            exe_path=exe if exe else "N/A",
            cmdline=cmdline,
            username=str(username),
            create_time=create_time,
            cpu_percent=0.0,
            memory_rss_bytes=mem_rss,
        )

    def _resolve_parent_name(self, ppid: int, raw: Dict[int, Dict[str, Any]]) -> str:
        if not ppid:
            return "N/A"
        parent = raw.get(ppid)
        if parent and parent.get("name"):
            return str(parent["name"]).lower()
        try:
            return psutil.Process(ppid).name().lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return "unknown"

    def _safe_exe_path(self, pid: int) -> str:
        try:
            return (psutil.Process(pid).exe() or "").strip()
        except (psutil.Error, OSError) as ex:
            logger.debug("exe() unavailable for PID %s: %s", pid, ex)
            return ""

    @staticmethod
    def _parse_create_time(raw_ct: Any) -> Optional[datetime]:
        return datetime.fromtimestamp(raw_ct) if raw_ct else None

    def build_process_tree(self) -> Dict[int, List[int]]:
        """Map parent PID to child PIDs."""
        self.process_tree = {}
        for pid, proc in self.processes.items():
            if proc.ppid:
                self.process_tree.setdefault(proc.ppid, []).append(pid)
        return self.process_tree

    def _create_process_alert(
        self,
        alert_type: str,
        severity: str,
        risk_score: int,
        process_name: str,
        pid: int,
        path: str,
        cmdline: Optional[str],
        username: Optional[str],
        reason: str,
        description: str,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        alert: Dict[str, Any] = {
            "type": alert_type,
            "severity": severity,
            "risk_score": risk_score,
            "timestamp": datetime.now(),
            "process_name": process_name,
            "pid": pid,
            "path": path,
            "reason": reason,
            "description": description,
        }
        if cmdline is not None:
            alert["cmdline"] = cmdline
        if username is not None:
            alert["username"] = username
        if extra:
            alert.update(extra)
        return alert

    def detect_suspicious_relationships(self) -> List[Dict[str, Any]]:
        """Office / LOLBAS-style parent-child chains."""
        anomalies: List[Dict[str, Any]] = []
        for pid, proc in self.processes.items():
            parent_name = proc.parent_name
            child_name = proc.name
            suspicious_children = config.SUSPICIOUS_RELATIONSHIPS.get(parent_name, ())
            if child_name not in suspicious_children:
                continue

            legitimate_children = config.LEGITIMATE_RELATIONSHIPS.get(parent_name, ())
            if child_name in legitimate_children:
                continue

            severity = config.SEVERITY_HIGH
            if parent_name in ("winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe"):
                severity = config.SEVERITY_CRITICAL

            parent_path = self.processes[proc.ppid].exe_path if proc.ppid and proc.ppid in self.processes else "N/A"
            child_path = proc.exe_path if proc.exe_path not in ("", "N/A") else ""
            path_value = child_path or proc.exe_path

            anomalies.append(
                self._create_process_alert(
                    "Suspicious Parent-Child Relationship",
                    severity,
                    _risk_score(severity, 5),
                    proc.name,
                    pid,
                    path_value,
                    proc.cmdline,
                    proc.username,
                    f"{parent_name} spawned {child_name}, which is commonly abused for code execution or payload staging.",
                    f"{parent_name} spawned {child_name} — review command line and network activity.",
                    {
                        "parent_name": parent_name,
                        "parent_pid": proc.ppid,
                        "parent_path": parent_path,
                        "child_name": child_name,
                        "child_pid": pid,
                        "child_path": path_value,
                    },
                )
            )
        self.anomalies.extend(anomalies)
        return anomalies

    def detect_unauthorized_processes(self) -> List[Dict[str, Any]]:
        """Blacklist hits and suspicious filesystem locations."""
        unauthorized: List[Dict[str, Any]] = []
        for pid, proc in self.processes.items():
            if proc.name in config.PROCESS_BLACKLIST:
                unauthorized.append(
                    self._create_process_alert(
                        "Blacklisted Process Detected",
                        config.SEVERITY_CRITICAL,
                        _risk_score(config.SEVERITY_CRITICAL),
                        proc.name,
                        pid,
                        proc.exe_path,
                        proc.cmdline,
                        proc.username,
                        "Process name matches a known offensive-tool indicator list.",
                        f"Blacklisted name: {proc.name}",
                    )
                )
                continue

            exe_lower = proc.exe_path.lower()
            if proc.exe_path == "N/A":
                continue

            matched_suspicious = False
            for fragment in config.SUSPICIOUS_PATH_FRAGMENTS:
                if fragment.lower() in exe_lower:
                    unauthorized.append(
                        self._create_process_alert(
                            "Process from Suspicious Location",
                            config.SEVERITY_MEDIUM,
                            _risk_score(config.SEVERITY_MEDIUM),
                            proc.name,
                            pid,
                            proc.exe_path,
                            proc.cmdline,
                            proc.username,
                            f"Binary path contains staging/temp pattern: {fragment}",
                            f"Process running from suspicious location: {proc.exe_path}",
                        )
                    )
                    matched_suspicious = True
                    break

            if matched_suspicious:
                continue

            for fragment in config.USER_WRITABLE_PATH_FRAGMENTS:
                if fragment.lower() in exe_lower and "program files" not in exe_lower:
                    unauthorized.append(
                        self._create_process_alert(
                            "Process from User-Writable Location",
                            config.SEVERITY_LOW,
                            _risk_score(config.SEVERITY_LOW, 10),
                            proc.name,
                            pid,
                            proc.exe_path,
                            proc.cmdline,
                            proc.username,
                            "Executable resides under a user-writable profile path.",
                            "Long-running binaries from user profiles warrant validation.",
                        )
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

            severity = config.SEVERITY_HIGH if any("enc" in h for h in hits) else config.SEVERITY_MEDIUM
            found.append(
                self._create_process_alert(
                    "Suspicious Command Line",
                    severity,
                    _risk_score(severity),
                    proc.name,
                    pid,
                    proc.exe_path,
                    proc.cmdline,
                    proc.username,
                    "Command line matches suspicious substring heuristics.",
                    f"Suspicious patterns in command line: {', '.join(hits[:5])}",
                    {"matched_patterns": hits},
                )
            )
        self.anomalies.extend(found)
        return found

    def detect_process_injection_signs(self) -> List[Dict[str, Any]]:
        """Missing image path (possible hollowing) and image/name mismatch."""
        indicators: List[Dict[str, Any]] = []
        for pid, proc in self.processes.items():
            if proc.exe_path == "N/A" and proc.name not in COMMON_SAFE_PROCESSES:
                indicators.append(
                    self._create_process_alert(
                        "Potential Process Injection",
                        config.SEVERITY_HIGH,
                        _risk_score(config.SEVERITY_HIGH),
                        proc.name,
                        pid,
                        proc.exe_path,
                        proc.cmdline,
                        proc.username,
                        "No valid executable path — may indicate hollowing or access limits.",
                        "Process running without a resolvable executable path.",
                    )
                )

            if proc.exe_path not in ("N/A", ""):
                exe_lower = proc.exe_path.lower()
                try:
                    base = os.path.basename(proc.exe_path).lower()
                    img_stem = os.path.splitext(base)[0]
                    proc_stem = os.path.splitext(proc.name)[0]
                    risky_path = any(x in exe_lower for x in TEMP_PATH_INDICATORS)
                    if base and risky_path and img_stem != proc_stem:
                        indicators.append(
                            self._create_process_alert(
                                "Image Name Mismatch",
                                config.SEVERITY_MEDIUM,
                                _risk_score(config.SEVERITY_MEDIUM),
                                proc.name,
                                pid,
                                proc.exe_path,
                                proc.cmdline,
                                proc.username,
                                "Image file name does not match process name under a risky path.",
                                f"Reported name {proc.name} vs on-disk {base}",
                            )
                        )
                except OSError:
                    pass

        self.anomalies.extend(indicators)
        return indicators

    def detect_orphan_processes(self) -> List[Dict[str, Any]]:
        """PPID does not map to a live process (excluding expected kernel parents)."""
        out: List[Dict[str, Any]] = []
        for pid, proc in self.processes.items():
            if proc.ppid in (0, 4) or proc.ppid == pid:
                continue
            if proc.ppid not in self.processes:
                out.append(
                    self._create_process_alert(
                        "Orphan or Hidden Parent Process",
                        config.SEVERITY_LOW,
                        _risk_score(config.SEVERITY_LOW, 5),
                        proc.name,
                        pid,
                        proc.exe_path,
                        proc.cmdline,
                        proc.username,
                        "Parent PID is not present in the enumerated snapshot (exited or protected).",
                        f"PPID {proc.ppid} not found for child {proc.name} ({pid}).",
                        {"ppid": proc.ppid},
                    )
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
                    self._create_process_alert(
                        "Duplicate Critical Process Name",
                        config.SEVERITY_CRITICAL,
                        _risk_score(config.SEVERITY_CRITICAL),
                        name,
                        pids[0] if pids else None,
                        path_field or "N/A",
                        None,
                        None,
                        "More than one instance of a process that is normally singular.",
                        f"{count} running instances of {name} — possible masquerading.",
                        {"pid_list": pids, "count": count},
                    )
                )

        for name, count in by_name.items():
            if count >= 4 and name not in COMMON_MULTI_INSTANCE_WHITELIST:
                paths = {p.exe_path for p in self.processes.values() if p.name == name}
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
                        self._create_process_alert(
                            "Duplicate Process Name (Many Paths)",
                            config.SEVERITY_MEDIUM,
                            _risk_score(config.SEVERITY_MEDIUM),
                            name,
                            sample_pid,
                            path_field or "N/A",
                            None,
                            None,
                            "Many concurrent processes share the same name from different paths.",
                            f"{count} instances of {name} from {len(paths)} locations.",
                            {"count": count, "distinct_paths": len(paths)},
                        )
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

    def detect_behavioral_anomalies(self) -> List[Dict[str, Any]]:
        """Detect behavioral anomalies using historical analysis and ML."""
        anomalies = self.behavior_analyzer.detect_anomalies()
        self.anomalies.extend(anomalies)
        return anomalies

    def detect_unknown_processes(self) -> List[Dict[str, Any]]:
        """Detect processes not present in baseline."""
        anomalies = self.behavior_analyzer.detect_unknown_processes(self.processes)
        self.anomalies.extend(anomalies)
        return anomalies

    def load_process_baseline(self, baseline_file: str) -> bool:
        """Load process baseline for unknown process detection."""
        return self.behavior_analyzer.ml_detector.load_baseline(baseline_file)

    def save_process_baseline(self, filename: str) -> str:
        """Save current process signatures as baseline."""
        return self.behavior_analyzer.ml_detector.save_baseline(self.processes, filename)

    def train_ml_model(self) -> bool:
        """Train ML model for anomaly detection."""
        # Collect training data from current behavior
        self.behavior_analyzer.collect_training_data()
        return self.behavior_analyzer.train_ml_model()

    def enable_baseline_mode(self, enabled: bool = True):
        """Enable/disable baseline collection mode."""
        self.behavior_analyzer.is_baseline_mode = enabled

    def cleanup_behavior_metrics(self):
        """Clean up old behavior metrics."""
        self.behavior_analyzer.cleanup_old_metrics()

    def get_all_anomalies(self) -> List[Dict[str, Any]]:
        return list(self.anomalies)
