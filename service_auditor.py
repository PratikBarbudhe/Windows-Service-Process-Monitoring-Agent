"""
Windows service auditing: enumeration via WMI (primary) with SCM fallback, and heuristics
for persistence and suspicious binary locations.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Set

import config

logger = logging.getLogger(__name__)

try:
    import win32service  # type: ignore
except ImportError:  # pragma: no cover
    win32service = None  # type: ignore

try:
    import wmi as wmi_module  # type: ignore
except ImportError:  # pragma: no cover
    wmi_module = None


@dataclass
class ServiceInfo:
    """Normalized Windows service record."""

    name: str
    display_name: str
    status: str
    start_type: str
    exe_path: str
    service_type: Any


def _path_under_system_prefixes(path_lower: str) -> bool:
    if not path_lower:
        return False
    for prefix in config.SYSTEM_SERVICE_PREFIXES:
        if path_lower.strip().startswith(prefix.lower()):
            return True
    return "system32" in path_lower or r"\windows\" in path_lower


def _extract_binary_path(path_name: str) -> str:
    """Normalize Win32_Service.PathName (handles quoted paths and arguments)."""
    if not path_name:
        return ""
    pn = path_name.strip()
    if pn.startswith('"'):
        end = pn.find('"', 1)
        if end != -1:
            return pn[1:end]
    parts = pn.split()
    return parts[0] if parts else pn


class ServiceAuditor:
    """Enumerate services and emit structured anomalies."""

    def __init__(self) -> None:
        self.services: Dict[str, ServiceInfo] = {}
        self.anomalies: List[Dict[str, Any]] = []

    def enumerate_services(self) -> Dict[str, ServiceInfo]:
        """Populate ``self.services`` using WMI when available, else SCM APIs."""
        self.services = {}
        if wmi_module is not None:
            try:
                self._enumerate_via_wmi()
            except Exception as exc:  # noqa: BLE001
                logger.warning("WMI enumeration failed (%s); falling back to SCM.", exc)
                self._enumerate_via_scm()
        else:
            self._enumerate_via_scm()
        return self.services

    def _enumerate_via_wmi(self) -> None:
        conn = wmi_module.WMI()  # type: ignore[attr-defined]
        for s in conn.Win32_Service():  # type: ignore[attr-defined]
            name = str(s.Name)
            display = str(s.DisplayName or "")
            state = str(s.State or "Unknown")
            start_mode = str(s.StartMode or "Unknown")
            path_name = str(s.PathName or "")
            binary = _extract_binary_path(path_name)
            svc_type = getattr(s, "ServiceType", None)
            self.services[name] = ServiceInfo(
                name=name,
                display_name=display,
                status=state,
                start_type=start_mode,
                exe_path=binary or path_name,
                service_type=svc_type,
            )

    def _enumerate_via_scm(self) -> None:
        if win32service is None:
            logger.error("pywin32 not available; cannot enumerate services.")
            return
        hscm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE)
        try:
            services = win32service.EnumServicesStatus(
                hscm, win32service.SERVICE_WIN32, win32service.SERVICE_STATE_ALL
            )
            start_type_map = {
                win32service.SERVICE_AUTO_START: "Auto",
                win32service.SERVICE_BOOT_START: "Boot",
                win32service.SERVICE_DEMAND_START: "Manual",
                win32service.SERVICE_DISABLED: "Disabled",
                win32service.SERVICE_SYSTEM_START: "System",
            }
            status_map = {
                win32service.SERVICE_STOPPED: "Stopped",
                win32service.SERVICE_START_PENDING: "Starting",
                win32service.SERVICE_STOP_PENDING: "Stopping",
                win32service.SERVICE_RUNNING: "Running",
                win32service.SERVICE_CONTINUE_PENDING: "Continuing",
                win32service.SERVICE_PAUSE_PENDING: "Pausing",
                win32service.SERVICE_PAUSED: "Paused",
            }
            for service in services:
                service_name = service[0]
                display_name = service[1]
                service_status = service[2]
                try:
                    hs = win32service.OpenService(hscm, service_name, win32service.SERVICE_QUERY_CONFIG)
                    try:
                        cfg = win32service.QueryServiceConfig(hs)
                        exe_path = cfg[3]
                    finally:
                        win32service.CloseServiceHandle(hs)
                    self.services[service_name] = ServiceInfo(
                        name=service_name,
                        display_name=display_name,
                        status=status_map.get(service_status[1], "Unknown"),
                        start_type=start_type_map.get(cfg[1], "Unknown"),
                        exe_path=exe_path,
                        service_type=cfg[0],
                    )
                except OSError:
                    continue
        finally:
            win32service.CloseServiceHandle(hscm)

    def detect_suspicious_services(self) -> List[Dict[str, Any]]:
        """Suspicious paths, non-system auto-start binaries, and kernel/driver oddities (light)."""
        anomalies: List[Dict[str, Any]] = []
        for service_name, info in self.services.items():
            exe_path = info.exe_path or ""
            exe_lower = exe_path.lower()

            for fragment in config.SUSPICIOUS_PATH_FRAGMENTS:
                if fragment.lower() in exe_lower:
                    anomalies.append(
                        {
                            "type": "Service from Suspicious Location",
                            "severity": config.SEVERITY_HIGH,
                            "risk_score": config.RISK_SCORES.get(config.SEVERITY_HIGH, 75),
                            "timestamp": datetime.now(),
                            "service_name": service_name,
                            "display_name": info.display_name,
                            "path": info.exe_path,
                            "status": info.status,
                            "start_type": info.start_type,
                            "reason": f"Service binary path contains: {fragment}",
                            "description": f"Service executable references suspicious location: {exe_path}",
                        }
                    )
                    break

            auto_like = info.start_type in ("Auto", "Boot", "System")
            if auto_like and info.status == "Running":
                if service_name.lower() not in config.LEGITIMATE_SERVICES:
                    if not _path_under_system_prefixes(exe_lower):
                        anomalies.append(
                            {
                                "type": "Auto-Start Service Outside System Directories",
                                "severity": config.SEVERITY_MEDIUM,
                                "risk_score": config.RISK_SCORES.get(config.SEVERITY_MEDIUM, 50),
                                "timestamp": datetime.now(),
                                "service_name": service_name,
                                "display_name": info.display_name,
                                "path": info.exe_path,
                                "status": info.status,
                                "start_type": info.start_type,
                                "reason": "Running auto-start service with binary outside typical Windows paths.",
                                "description": f"Review legitimacy of auto-start service {service_name}.",
                            }
                        )

            if exe_path and re.search(r"\.(bat|cmd|ps1|vbs|js)\b", exe_lower):
                anomalies.append(
                    {
                        "type": "Service Hosting Script Interpreter",
                        "severity": config.SEVERITY_HIGH,
                        "risk_score": config.RISK_SCORES.get(config.SEVERITY_HIGH, 75),
                        "timestamp": datetime.now(),
                        "service_name": service_name,
                        "display_name": info.display_name,
                        "path": info.exe_path,
                        "status": info.status,
                        "start_type": info.start_type,
                        "reason": "Service points to a script file — uncommon for built-in services.",
                        "description": "Persistence often abuses script-based service binaries.",
                    }
                )

        self.anomalies.extend(anomalies)
        return anomalies

    def detect_new_services(self, baseline_services: Iterable[str]) -> List[Dict[str, Any]]:
        """Services present now but absent from baseline name set."""
        baseline_set = set(baseline_services)
        new_services: List[Dict[str, Any]] = []
        for service_name in set(self.services.keys()) - baseline_set:
            info = self.services[service_name]
            new_services.append(
                {
                    "type": "Newly Added Service",
                    "severity": config.SEVERITY_MEDIUM,
                    "risk_score": config.RISK_SCORES.get(config.SEVERITY_MEDIUM, 50),
                    "timestamp": datetime.now(),
                    "service_name": service_name,
                    "display_name": info.display_name,
                    "path": info.exe_path,
                    "status": info.status,
                    "start_type": info.start_type,
                    "reason": "Service name not present in stored baseline snapshot.",
                    "description": f"New service detected compared to baseline: {service_name}",
                }
            )
        self.anomalies.extend(new_services)
        return new_services

    def get_startup_services(self) -> List[ServiceInfo]:
        return [s for s in self.services.values() if s.start_type in ("Auto", "Boot", "System")]

    def get_all_anomalies(self) -> List[Dict[str, Any]]:
        return list(self.anomalies)


def build_baseline_payload(services: Dict[str, ServiceInfo]) -> Dict[str, Any]:
    """Richer baseline for SOC portfolios (names + paths + start type)."""
    entries = [
        {
            "name": s.name,
            "display_name": s.display_name,
            "path": s.exe_path,
            "start_type": s.start_type,
        }
        for s in services.values()
    ]
    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "service_count": len(services),
        "services": entries,
        "service_names": sorted(services.keys()),
    }


def baseline_names_from_file(data: Dict[str, Any]) -> Set[str]:
    """Support both legacy baselines (list of strings) and rich baselines."""
    if "service_names" in data:
        return set(data["service_names"])
    services = data.get("services")
    if isinstance(services, list) and services and isinstance(services[0], str):
        return set(services)
    if isinstance(services, list) and services and isinstance(services[0], dict):
        return {str(x.get("name")) for x in services if x.get("name")}
    return set()
