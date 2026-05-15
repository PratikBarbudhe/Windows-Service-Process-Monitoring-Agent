"""
Core application package.

Module map:
  config           - settings from .env
  constants        - shared UI constants (refresh intervals, limits)
  models           - ProcessInfo, Alert, ScanResult dataclasses
  process_display  - Task Manager names, CPU normalization, false-positive filters
  process_ranking  - Top-N processes by CPU or memory
  monitoring       - MonitoringAgent (scans, alerts, log files)
  logging_setup    - log configuration
"""
