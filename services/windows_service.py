from __future__ import annotations

import logging
import time

from app.config import settings
from app.monitoring import MonitoringAgent

logger = logging.getLogger(__name__)


def run_service_loop() -> None:
    """Service-safe loop used by a Windows service host."""
    agent = MonitoringAgent()
    while True:
        try:
            agent.run_scan()
            time.sleep(settings.scan_interval)
        except KeyboardInterrupt:
            logger.info("Service loop interrupted")
            break
        except Exception as exc:  # noqa: BLE001
            logger.exception("Service loop scan failed: %s", exc)
            time.sleep(min(settings.scan_interval, 30))

