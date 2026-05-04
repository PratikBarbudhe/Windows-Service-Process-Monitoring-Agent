from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional dependency during bootstrap
    load_dotenv = None

if load_dotenv:
    load_dotenv()


@dataclass(frozen=True)
class Settings:
    app_name: str = os.getenv("APP_NAME", "Windows Service Process Monitoring Agent")
    app_env: str = os.getenv("APP_ENV", "development")
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    output_dir: Path = Path(os.getenv("OUTPUT_DIR", "output"))
    report_dir: Path = Path(os.getenv("REPORT_DIR", "reports"))
    log_dir: Path = Path(os.getenv("LOG_DIR", "logs"))
    api_host: str = os.getenv("API_HOST", "0.0.0.0")
    api_port: int = int(os.getenv("API_PORT", "8000"))
    api_token: str = os.getenv("API_TOKEN", "change-me")
    scan_interval: int = int(os.getenv("SCAN_INTERVAL", "60"))


settings = Settings()

