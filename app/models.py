from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Optional

@dataclass
class ProcessInfo:
    pid: int
    name: str
    username: Optional[str] = None
    exe: Optional[str] = None
    cpu_percent: float = 0.0
    memory_mb: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Alert:
    type: str
    severity: str
    message: str
    process_name: Optional[str] = None
    pid: Optional[int] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload["created_at"] = self.created_at.isoformat()
        return payload


@dataclass
class ScanResult:
    processes: list[ProcessInfo]
    alerts: list[Alert]
    scanned_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return {
            "scanned_at": self.scanned_at.isoformat(),
            "processes": [item.to_dict() for item in self.processes],
            "alerts": [item.to_dict() for item in self.alerts],
        }

