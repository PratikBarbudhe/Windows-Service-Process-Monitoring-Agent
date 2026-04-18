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

# Win32 Service status and start type mappings for SCM enumeration
WIN32_START_TYPE_MAP = {
    win32service.SERVICE_AUTO_START: "Auto",
    win32service.SERVICE_BOOT_START: "Boot",
    win32service.SERVICE_DEMAND_START: "Manual",
    win32service.SERVICE_DISABLED: "Disabled",
    win32service.SERVICE_SYSTEM_START: "System",
} if win32service else {}

WIN32_STATUS_MAP = {
    win32service.SERVICE_STOPPED: "Stopped",
    win32service.SERVICE_START_PENDING: "Starting",
    win32service.SERVICE_STOP_PENDING: "Stopping",
    win32service.SERVICE_RUNNING: "Running",
    win32service.SERVICE_CONTINUE_PENDING: "Continuing",
    win32service.SERVICE_PAUSE_PENDING: "Pausing",
    win32service.SERVICE_PAUSED: "Paused",
} if win32service else {}

SCRIPT_INTERPRETER_PATTERN = r"\.(bat|cmd|ps1|vbs|js)\b"


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
    """Check if path falls under known Windows system directories."""
    if not path_lower:
        return False
    for prefix in config.SYSTEM_SERVICE_PREFIXES:
        if path_lower.strip().startswith(prefix.lower()):
            return True
    return "system32" in path_lower or "\\windows\\" in path_lower


def _extract_binary_path(path_name: str) -> str:
    """Normalize Win32_Service.PathName (handles quoted paths and arguments)."""
    if not path_name:
        return ""
    normalized = path_name.strip()
    if normalized.startswith('"'):
        end = normalized.find('"', 1)
        if end != -1:
            return normalized[1:end]
    parts = normalized.split()
    return parts[0] if parts else normalized


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
        """Enumerate services using WMI (primary method)."""
        conn = wmi_module.WMI()  # type: ignore[attr-defined]
        for svc in conn.Win32_Service():  # type: ignore[attr-defined]
            name = str(svc.Name)
            display_name = str(svc.DisplayName or "")
            status = str(svc.State or "Unknown")
            start_type = str(svc.StartMode or "Unknown")
            path_name = str(svc.PathName or "")
            exe_path = _extract_binary_path(path_name)
            service_type = getattr(svc, "ServiceType", None)
            
            self.services[name] = ServiceInfo(
                name=name,
                display_name=display_name,
                status=status,
                start_type=start_type,
                exe_path=exe_path or path_name,
                service_type=service_type,
            )

    def _enumerate_via_scm(self) -> None:
        """Enumerate services using SCM APIs (fallback method)."""
        if win32service is None:
            logger.error("pywin32 not available; cannot enumerate services.")
            return
        
        hscm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE)
        try:
            services = win32service.EnumServicesStatus(
                hscm, win32service.SERVICE_WIN32, win32service.SERVICE_STATE_ALL
            )
            for service_tuple in services:
                self._process_scm_service(service_tuple, hscm)
        finally:
            win32service.CloseServiceHandle(hscm)

    def _process_scm_service(self, service_tuple: tuple, hscm: Any) -> None:
        """Process a single service from SCM enumeration."""
        name = service_tuple[0]
        display_name = service_tuple[1]
        service_status_code = service_tuple[2][1]
        
        try:
            service_handle = win32service.OpenService(
                hscm, name, win32service.SERVICE_QUERY_CONFIG
            )
            try:
                config_tuple = win32service.QueryServiceConfig(service_handle)
                exe_path = config_tuple[3]
                service_type = config_tuple[0]
                start_type_code = config_tuple[1]
            finally:
                win32service.CloseServiceHandle(service_handle)
            
            self.services[name] = ServiceInfo(
                name=name,
                display_name=display_name,
                status=WIN32_STATUS_MAP.get(service_status_code, "Unknown"),
                start_type=WIN32_START_TYPE_MAP.get(start_type_code, "Unknown"),
                exe_path=exe_path,
                service_type=service_type,
            )
        except Exception:
            pass

    def _create_service_alert(
        self,
        alert_type: str,
        severity: str,
        service_info: ServiceInfo,
        reason: str,
        description: str,
    ) -> Dict[str, Any]:
        """Create a structured service anomaly alert."""
        return {
            "type": alert_type,
            "severity": severity,
            "risk_score": config.RISK_SCORES.get(severity, 50),
            "timestamp": datetime.now(),
            "service_name": service_info.name,
            "display_name": service_info.display_name,
            "path": service_info.exe_path,
            "status": service_info.status,
            "start_type": service_info.start_type,
            "reason": reason,
            "description": description,
        }

    def detect_suspicious_services(self) -> List[Dict[str, Any]]:
        """Suspicious paths, non-system auto-start binaries, and script hosting."""
        anomalies: List[Dict[str, Any]] = []
        
        for service_info in self.services.values():
            exe_path_lower = (service_info.exe_path or "").lower()
            
            # Check for suspicious path fragments
            for fragment in config.SUSPICIOUS_PATH_FRAGMENTS:
                if fragment.lower() in exe_path_lower:
                    anomalies.append(
                        self._create_service_alert(
                            "Service from Suspicious Location",
                            config.SEVERITY_HIGH,
                            service_info,
                            f"Service binary path contains: {fragment}",
                            f"Service executable references suspicious location: {service_info.exe_path}",
                        )
                    )
                    break
            
            # Check for auto-start services outside system directories
            is_auto_start = service_info.start_type in ("Auto", "Boot", "System")
            is_running = service_info.status == "Running"
            is_legitimate = service_info.name.lower() in config.LEGITIMATE_SERVICES
            is_system_path = _path_under_system_prefixes(exe_path_lower)
            
            if is_auto_start and is_running and not is_legitimate and not is_system_path:
                anomalies.append(
                    self._create_service_alert(
                        "Auto-Start Service Outside System Directories",
                        config.SEVERITY_MEDIUM,
                        service_info,
                        "Running auto-start service with binary outside typical Windows paths.",
                        f"Review legitimacy of auto-start service {service_info.name}.",
                    )
                )
            
            # Check for script interpreter hosting
            if service_info.exe_path and re.search(SCRIPT_INTERPRETER_PATTERN, exe_path_lower):
                anomalies.append(
                    self._create_service_alert(
                        "Service Hosting Script Interpreter",
                        config.SEVERITY_HIGH,
                        service_info,
                        "Service points to a script file — uncommon for built-in services.",
                        "Persistence often abuses script-based service binaries.",
                    )
                )
        
        self.anomalies.extend(anomalies)
        return anomalies

    def detect_new_services(self, baseline_services: Iterable[str]) -> List[Dict[str, Any]]:
        """Detect services present now but absent from baseline."""
        baseline_set = set(baseline_services)
        new_anomalies: List[Dict[str, Any]] = []
        
        for service_name in set(self.services.keys()) - baseline_set:
            service_info = self.services[service_name]
            new_anomalies.append(
                self._create_service_alert(
                    "Newly Added Service",
                    config.SEVERITY_MEDIUM,
                    service_info,
                    "Service name not present in stored baseline snapshot.",
                    f"New service detected compared to baseline: {service_name}",
                )
            )
        
        self.anomalies.extend(new_anomalies)
        return new_anomalies

    def get_startup_services(self) -> List[ServiceInfo]:
        """Return all auto/boot/system startup services."""
        return [
            s for s in self.services.values()
            if s.start_type in ("Auto", "Boot", "System")
        ]

    def get_all_anomalies(self) -> List[Dict[str, Any]]:
        """Return all collected anomalies."""
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
