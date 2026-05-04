from __future__ import annotations

import argparse
import logging
import time

from app.config import settings
from app.monitoring import MonitoringAgent

logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Windows monitoring agent CLI")
    parser.add_argument("--continuous", action="store_true", help="Run in continuous mode")
    parser.add_argument("--interval", type=int, default=settings.scan_interval, help="Scan interval in seconds")
    return parser


def run_cli() -> None:
    args = build_parser().parse_args()
    agent = MonitoringAgent()

    if args.continuous:
        logger.info("Starting continuous mode with %ss interval", args.interval)
        while True:
            try:
                agent.run_scan()
                time.sleep(args.interval)
            except KeyboardInterrupt:
                logger.info("Stopped by user")
                break
            except Exception as exc:  # noqa: BLE001
                logger.exception("Continuous scan iteration failed: %s", exc)
                time.sleep(min(args.interval, 30))
    else:
        agent.run_scan()

