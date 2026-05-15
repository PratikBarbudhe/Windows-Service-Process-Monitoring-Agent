from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query, status

from app.config import settings
from app.monitoring import MonitoringAgent

logger = logging.getLogger(__name__)
app = FastAPI(title=settings.app_name, version="1.0.0")
agent = MonitoringAgent()


def verify_token(x_api_token: str = Header(default="")) -> None:
    if x_api_token != settings.api_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API token",
        )


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.post("/scan", dependencies=[Depends(verify_token)])
def run_scan() -> dict:
    try:
        result = agent.run_scan()
        return result.to_dict()
    except Exception as exc:  # noqa: BLE001
        logger.exception("API scan failed: %s", exc)
        raise HTTPException(status_code=500, detail="Scan failed") from exc


@app.get("/alerts", dependencies=[Depends(verify_token)])
def get_alerts() -> dict:
    if agent.alerts:
        return {"alerts": [alert.to_dict() for alert in agent.alerts]}
    return {"alerts": agent.load_latest_alerts()}


@app.get("/processes", dependencies=[Depends(verify_token)])
def get_processes() -> dict:
    try:
        return {"processes": agent.get_process_snapshot()}
    except Exception as exc:  # noqa: BLE001
        logger.exception("API process snapshot failed: %s", exc)
        raise HTTPException(status_code=500, detail="Process snapshot failed") from exc


@app.get("/status", dependencies=[Depends(verify_token)])
def get_status() -> dict:
    """Get overall system status including alerts summary and last scan time."""
    try:
        alerts = agent.alerts
        processes = agent.get_process_snapshot()
        
        # Calculate system metrics
        total_cpu = sum(p.get("cpu_percent", 0) for p in processes)
        avg_cpu = total_cpu / len(processes) if processes else 0
        total_memory = sum(p.get("memory_mb", 0) for p in processes)
        
        # Count alerts by severity
        severity_counts = {}
        for alert in alerts:
            severity = alert.get("severity", "UNKNOWN") if isinstance(alert, dict) else getattr(alert, "severity", "UNKNOWN")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            "status": "healthy" if not alerts else "warning",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_alerts": len(alerts),
            "severity_counts": severity_counts,
            "process_count": len(processes),
            "avg_cpu_percent": round(avg_cpu, 2),
            "total_memory_mb": round(total_memory, 2),
        }
    except Exception as exc:  # noqa: BLE001
        logger.exception("API status failed: %s", exc)
        raise HTTPException(status_code=500, detail="Status retrieval failed") from exc


@app.get("/logs", dependencies=[Depends(verify_token)])
def get_logs(limit: int = Query(100, ge=1, le=1000), level: str = Query("INFO")) -> dict:
    """Get recent log entries with optional filtering."""
    try:
        logs = []
        log_file = settings.log_dir / "agent.log"
        
        if log_file.exists():
            try:
                # Read log file and parse lines
                with open(log_file, encoding="utf-8") as f:
                    lines = f.readlines()
                
                # Parse log entries - format: "timestamp | level | logger | message"
                for line in reversed(lines[-limit:]):
                    line = line.strip()
                    if not line:
                        continue
                    
                    parts = line.split(" | ", 3)
                    if len(parts) >= 4:
                        timestamp, log_level, logger_name, message = parts[0], parts[1], parts[2], parts[3]
                        
                        # Filter by level if specified
                        if level.upper() != "ALL" and log_level != level.upper():
                            continue
                        
                        logs.append({
                            "timestamp": timestamp,
                            "level": log_level,
                            "logger": logger_name,
                            "message": message,
                        })
            except (IOError, OSError) as exc:
                logger.warning("Could not read log file: %s", exc)
        
        return {
            "logs": logs[:limit],
            "total": len(logs),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as exc:  # noqa: BLE001
        logger.exception("API logs failed: %s", exc)
        raise HTTPException(status_code=500, detail="Logs retrieval failed") from exc

