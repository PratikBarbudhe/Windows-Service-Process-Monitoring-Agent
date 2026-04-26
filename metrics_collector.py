"""
Metrics Collector - Tracks system metrics over time for visualization

Collects and stores:
- CPU usage per process
- Memory usage per process
- Process creation/termination
- System-wide CPU/memory trends
- Top processes by resource usage

Data is stored in JSON files and can be queried for time-series visualization.
"""

from __future__ import annotations

import json
import logging
import os
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import psutil

import config

logger = logging.getLogger(__name__)

# Metrics retention (keep last N days of data)
METRICS_RETENTION_DAYS = 7

# Collection interval (seconds) - collect metrics every 5 minutes
COLLECTION_INTERVAL = 300


@dataclass
class ProcessMetric:
    """Point-in-time snapshot of a process's resource usage."""

    timestamp: str
    pid: int
    name: str
    path: str
    cpu_percent: float
    memory_mb: float
    memory_percent: float
    num_threads: int
    handles: int
    io_read_bytes: Optional[int] = None
    io_write_bytes: Optional[int] = None
    nice: int = 0
    user: Optional[str] = None


@dataclass
class SystemMetric:
    """Point-in-time snapshot of system-wide metrics."""

    timestamp: str
    cpu_percent: float
    memory_percent: float
    memory_available_mb: float
    disk_usage_percent: float
    network_bytes_sent: int = 0
    network_bytes_recv: int = 0
    process_count: int = 0
    thread_count: int = 0


@dataclass
class MetricsSnapshot:
    """Complete snapshot of all metrics at a point in time."""

    system: SystemMetric
    processes: List[ProcessMetric] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class MetricsCollector:
    """Collects and stores system metrics for visualization."""

    def __init__(self, data_dir: str = "metrics"):
        """Initialize metrics collector."""
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)

        # Metrics storage
        self.current_snapshot: Optional[MetricsSnapshot] = None
        self.history_file = self.data_dir / "metrics_history.jsonl"
        self.daily_summaries_dir = self.data_dir / "daily_summaries"
        self.daily_summaries_dir.mkdir(exist_ok=True)

        logger.info(f"MetricsCollector initialized (data_dir: {self.data_dir})")

    def collect_snapshot(self) -> MetricsSnapshot:
        """
        Collect a complete snapshot of system and process metrics.

        Returns:
            MetricsSnapshot with current system and process metrics
        """
        try:
            timestamp = datetime.now().isoformat()

            # Collect system metrics
            system_metric = self._collect_system_metrics(timestamp)

            # Collect process metrics
            process_metrics = self._collect_process_metrics(timestamp)

            snapshot = MetricsSnapshot(
                system=system_metric, processes=process_metrics, timestamp=timestamp
            )

            self.current_snapshot = snapshot
            self._save_snapshot(snapshot)

            logger.debug(f"Collected metrics snapshot: {len(process_metrics)} processes")
            return snapshot

        except Exception as e:
            logger.error(f"Error collecting metrics: {e}")
            return None

    def _collect_system_metrics(self, timestamp: str) -> SystemMetric:
        """Collect system-wide metrics."""
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage("/")

            return SystemMetric(
                timestamp=timestamp,
                cpu_percent=cpu_percent,
                memory_percent=memory.percent,
                memory_available_mb=memory.available / (1024 * 1024),
                disk_usage_percent=disk.percent,
                process_count=len(psutil.pids()),
                thread_count=sum(
                    psutil.Process(pid).num_threads()
                    for pid in psutil.pids()
                    if self._is_process_accessible(pid)
                ),
            )
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
            # Return default values
            return SystemMetric(timestamp=timestamp, cpu_percent=0, memory_percent=0, memory_available_mb=0, disk_usage_percent=0)

    def _collect_process_metrics(self, timestamp: str) -> List[ProcessMetric]:
        """Collect metrics for all running processes."""
        process_metrics = []

        try:
            for proc in psutil.process_iter(
                attrs=["pid", "name", "exe", "cpu_percent", "memory_info", "num_threads", "num_handles"]
            ):
                try:
                    if not self._is_process_accessible(proc.pid):
                        continue

                    with proc.oneshot():
                        memory_mb = proc.memory_info().rss / (1024 * 1024)
                        memory_percent = proc.memory_percent()

                        metric = ProcessMetric(
                            timestamp=timestamp,
                            pid=proc.pid,
                            name=proc.name(),
                            path=proc.exe() or "Unknown",
                            cpu_percent=proc.cpu_percent() or 0,
                            memory_mb=memory_mb,
                            memory_percent=memory_percent,
                            num_threads=proc.num_threads(),
                            handles=proc.num_handles(),
                            nice=proc.nice(),
                        )
                        process_metrics.append(metric)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

        except Exception as e:
            logger.error(f"Error collecting process metrics: {e}")

        return process_metrics

    def _is_process_accessible(self, pid: int) -> bool:
        """Check if process is accessible."""
        try:
            proc = psutil.Process(pid)
            # Try to access a basic attribute
            proc.status()
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return False

    def _save_snapshot(self, snapshot: MetricsSnapshot) -> None:
        """Save snapshot to history file (JSONL format)."""
        try:
            snapshot_dict = {
                "timestamp": snapshot.timestamp,
                "system": asdict(snapshot.system),
                "processes": [asdict(p) for p in snapshot.processes],
            }

            # Append to history file
            with open(self.history_file, "a") as f:
                f.write(json.dumps(snapshot_dict) + "\n")

        except Exception as e:
            logger.error(f"Error saving snapshot: {e}")

    def get_metrics_window(
        self, hours: int = 1, limit: Optional[int] = None
    ) -> List[MetricsSnapshot]:
        """
        Get metrics from the last N hours.

        Args:
            hours: Number of hours to look back
            limit: Maximum number of snapshots to return

        Returns:
            List of MetricsSnapshot objects
        """
        try:
            snapshots = []
            cutoff_time = datetime.now() - timedelta(hours=hours)

            if not self.history_file.exists():
                return snapshots

            with open(self.history_file, "r") as f:
                for line in f:
                    if not line.strip():
                        continue

                    try:
                        data = json.loads(line)
                        timestamp = datetime.fromisoformat(data["timestamp"])

                        if timestamp >= cutoff_time:
                            snapshot = MetricsSnapshot(
                                system=SystemMetric(**data["system"]),
                                processes=[ProcessMetric(**p) for p in data["processes"]],
                                timestamp=data["timestamp"],
                            )
                            snapshots.append(snapshot)
                    except Exception as e:
                        logger.debug(f"Error parsing snapshot: {e}")
                        continue

            if limit:
                snapshots = snapshots[-limit:]

            return snapshots

        except Exception as e:
            logger.error(f"Error reading metrics window: {e}")
            return []

    def get_cpu_usage_timeline(self, hours: int = 1) -> List[Dict[str, Any]]:
        """
        Get CPU usage timeline for charts.

        Returns list of {timestamp, cpu_percent} for system and per-process.
        """
        snapshots = self.get_metrics_window(hours=hours)

        timeline = []
        for snapshot in snapshots:
            timeline.append(
                {
                    "timestamp": snapshot.timestamp,
                    "system_cpu": snapshot.system.cpu_percent,
                    "process_count": len(snapshot.processes),
                }
            )

        return timeline

    def get_memory_usage_timeline(self, hours: int = 1) -> List[Dict[str, Any]]:
        """Get memory usage timeline for charts."""
        snapshots = self.get_metrics_window(hours=hours)

        timeline = []
        for snapshot in snapshots:
            timeline.append(
                {
                    "timestamp": snapshot.timestamp,
                    "system_memory_percent": snapshot.system.memory_percent,
                    "memory_available_mb": snapshot.system.memory_available_mb,
                }
            )

        return timeline

    def get_top_processes_by_cpu(
        self, hours: int = 1, limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Get top processes by average CPU usage."""
        snapshots = self.get_metrics_window(hours=hours)

        # Aggregate CPU usage by process
        process_cpu = defaultdict(list)
        for snapshot in snapshots:
            for proc in snapshot.processes:
                process_cpu[proc.name].append(proc.cpu_percent)

        # Calculate averages
        top_processes = []
        for name, cpu_values in process_cpu.items():
            avg_cpu = sum(cpu_values) / len(cpu_values)
            max_cpu = max(cpu_values)
            top_processes.append(
                {"name": name, "avg_cpu": avg_cpu, "max_cpu": max_cpu, "samples": len(cpu_values)}
            )

        # Sort and limit
        top_processes.sort(key=lambda x: x["avg_cpu"], reverse=True)
        return top_processes[:limit]

    def get_top_processes_by_memory(
        self, hours: int = 1, limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Get top processes by average memory usage."""
        snapshots = self.get_metrics_window(hours=hours)

        # Aggregate memory usage by process
        process_memory = defaultdict(list)
        for snapshot in snapshots:
            for proc in snapshot.processes:
                process_memory[proc.name].append(proc.memory_mb)

        # Calculate averages
        top_processes = []
        for name, memory_values in process_memory.items():
            avg_memory = sum(memory_values) / len(memory_values)
            max_memory = max(memory_values)
            top_processes.append(
                {
                    "name": name,
                    "avg_memory_mb": avg_memory,
                    "max_memory_mb": max_memory,
                    "samples": len(memory_values),
                }
            )

        # Sort and limit
        top_processes.sort(key=lambda x: x["avg_memory_mb"], reverse=True)
        return top_processes[:limit]

    def get_process_cpu_timeline(
        self, process_name: str, hours: int = 1
    ) -> List[Dict[str, Any]]:
        """Get CPU usage timeline for a specific process."""
        snapshots = self.get_metrics_window(hours=hours)

        timeline = []
        for snapshot in snapshots:
            processes = [p for p in snapshot.processes if p.name == process_name]
            if processes:
                # Sum CPU across all instances of this process
                cpu = sum(p.cpu_percent for p in processes)
                timeline.append({"timestamp": snapshot.timestamp, "cpu": cpu})

        return timeline

    def get_process_memory_timeline(
        self, process_name: str, hours: int = 1
    ) -> List[Dict[str, Any]]:
        """Get memory usage timeline for a specific process."""
        snapshots = self.get_metrics_window(hours=hours)

        timeline = []
        for snapshot in snapshots:
            processes = [p for p in snapshot.processes if p.name == process_name]
            if processes:
                # Sum memory across all instances of this process
                memory = sum(p.memory_mb for p in processes)
                timeline.append({"timestamp": snapshot.timestamp, "memory_mb": memory})

        return timeline

    def cleanup_old_data(self) -> None:
        """Remove metrics data older than retention period."""
        try:
            cutoff_time = datetime.now() - timedelta(days=METRICS_RETENTION_DAYS)

            if not self.history_file.exists():
                return

            # Read all valid snapshots
            valid_snapshots = []
            with open(self.history_file, "r") as f:
                for line in f:
                    if not line.strip():
                        continue

                    try:
                        data = json.loads(line)
                        timestamp = datetime.fromisoformat(data["timestamp"])

                        if timestamp >= cutoff_time:
                            valid_snapshots.append(line.strip())
                    except Exception:
                        continue

            # Write back only valid snapshots
            with open(self.history_file, "w") as f:
                for snapshot in valid_snapshots:
                    f.write(snapshot + "\n")

            logger.info(
                f"Cleaned up metrics data older than {METRICS_RETENTION_DAYS} days"
            )

        except Exception as e:
            logger.error(f"Error cleaning up metrics: {e}")

    def get_summary_stats(self, hours: int = 24) -> Dict[str, Any]:
        """Get summary statistics for the given time period."""
        snapshots = self.get_metrics_window(hours=hours)

        if not snapshots:
            return {}

        # CPU stats
        cpu_values = [s.system.cpu_percent for s in snapshots]
        
        # Memory stats
        memory_values = [s.system.memory_percent for s in snapshots]

        # Process stats
        all_process_names = set()
        for snapshot in snapshots:
            for proc in snapshot.processes:
                all_process_names.add(proc.name)

        return {
            "time_period_hours": hours,
            "snapshot_count": len(snapshots),
            "unique_processes": len(all_process_names),
            "cpu_avg": sum(cpu_values) / len(cpu_values) if cpu_values else 0,
            "cpu_max": max(cpu_values) if cpu_values else 0,
            "cpu_min": min(cpu_values) if cpu_values else 0,
            "memory_avg_percent": sum(memory_values) / len(memory_values) if memory_values else 0,
            "memory_max_percent": max(memory_values) if memory_values else 0,
            "memory_min_percent": min(memory_values) if memory_values else 0,
        }
