from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, Header, HTTPException, status

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
    return {"alerts": [alert.to_dict() for alert in agent.alerts]}

