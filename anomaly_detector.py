"""
Machine Learning-based anomaly detection for process monitoring.

Implements behavior-based detection using Isolation Forest and statistical methods
to identify unusual CPU usage, memory leaks, and anomalous process behavior.
"""

from __future__ import annotations

import json
import logging
import os
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

import config

logger = logging.getLogger(__name__)


class ProcessMetrics:
    """Container for process performance metrics over time."""

    def __init__(self, pid: int, name: str):
        self.pid = pid
        self.name = name
        self.cpu_history: List[float] = []
        self.memory_history: List[int] = []
        self.thread_count_history: List[int] = []
        self.timestamps: List[datetime] = []
        self.baseline_cpu_mean: Optional[float] = None
        self.baseline_cpu_std: Optional[float] = None
        self.baseline_memory_mean: Optional[float] = None
        self.baseline_memory_std: Optional[float] = None

    def add_measurement(self, cpu_percent: float, memory_rss: int, thread_count: int, timestamp: Optional[datetime] = None):
        """Add a new measurement to the history."""
        if timestamp is None:
            timestamp = datetime.now()

        self.cpu_history.append(cpu_percent)
        self.memory_history.append(memory_rss)
        self.thread_count_history.append(thread_count)
        self.timestamps.append(timestamp)

        # Keep only recent history (last 100 measurements)
        max_history = config.BEHAVIOR_HISTORY_LENGTH
        if len(self.cpu_history) > max_history:
            self.cpu_history.pop(0)
            self.memory_history.pop(0)
            self.thread_count_history.pop(0)
            self.timestamps.pop(0)

    def calculate_baselines(self, min_samples: int = config.MIN_BASELINE_SAMPLES):
        """Calculate baseline statistics from historical data."""
        if len(self.cpu_history) < min_samples:
            return

        self.baseline_cpu_mean = np.mean(self.cpu_history)
        self.baseline_cpu_std = np.std(self.cpu_history)
        self.baseline_memory_mean = np.mean(self.memory_history)
        self.baseline_memory_std = np.std(self.memory_history)

    def detect_cpu_spike(self, current_cpu: float, threshold_sigma: float = config.CPU_SPIKE_THRESHOLD_SIGMA) -> bool:
        """Detect unusual CPU usage spike."""
        if self.baseline_cpu_mean is None or self.baseline_cpu_std is None:
            return False

        # Only flag as spike if significantly above baseline and absolute usage is high
        return (current_cpu > self.baseline_cpu_mean + (threshold_sigma * self.baseline_cpu_std) and
                current_cpu > 50.0)  # Absolute threshold to avoid false positives on low-usage processes

    def detect_memory_leak(self, current_memory: int, threshold_sigma: float = config.MEMORY_LEAK_THRESHOLD_SIGMA) -> bool:
        """Detect potential memory leak based on trend."""
        if len(self.memory_history) < 5:
            return False

        # Check if memory is consistently increasing
        recent_memory = self.memory_history[-5:]
        if len(recent_memory) < 5:
            return False

        # Calculate trend (simple linear regression slope)
        x = np.arange(len(recent_memory))
        slope = np.polyfit(x, recent_memory, 1)[0]

        # Positive slope indicates increasing memory usage
        if slope <= 0:
            return False

        # Check if current memory is above baseline
        if self.baseline_memory_mean is None or self.baseline_memory_std is None:
            return False

        return current_memory > self.baseline_memory_mean + (threshold_sigma * self.baseline_memory_std)

    def get_features(self) -> np.ndarray:
        """Extract features for ML model."""
        if len(self.cpu_history) < 3:
            return np.array([])

        # Calculate statistical features
        cpu_mean = np.mean(self.cpu_history)
        cpu_std = np.std(self.cpu_history)
        cpu_max = np.max(self.cpu_history)
        cpu_min = np.min(self.cpu_history)

        memory_mean = np.mean(self.memory_history)
        memory_std = np.std(self.memory_history)
        memory_max = np.max(self.memory_history)
        memory_min = np.min(self.memory_history)

        thread_mean = np.mean(self.thread_count_history)
        thread_std = np.std(self.thread_count_history)

        # Calculate trends (slope of last few points)
        cpu_trend = np.polyfit(np.arange(len(self.cpu_history)), self.cpu_history, 1)[0]
        memory_trend = np.polyfit(np.arange(len(self.memory_history)), self.memory_history, 1)[0]

        return np.array([
            cpu_mean, cpu_std, cpu_max, cpu_min, cpu_trend,
            memory_mean, memory_std, memory_max, memory_min, memory_trend,
            thread_mean, thread_std
        ])


class MLAnomalyDetector:
    """Machine learning-based anomaly detection using Isolation Forest."""

    def __init__(self, contamination: float = config.ML_MODEL_CONTAMINATION, random_state: int = config.ML_MODEL_RANDOM_STATE):
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self.is_trained = False
        self.contamination = contamination
        self.random_state = random_state
        self.baseline_processes: Set[str] = set()

    def load_baseline(self, baseline_file: str) -> bool:
        """Load baseline process signatures from file."""
        try:
            with open(baseline_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            if 'baseline_processes' in data:
                self.baseline_processes = set(data['baseline_processes'])
                logger.info(f"Loaded {len(self.baseline_processes)} baseline processes")
                return True

        except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
            logger.warning(f"Could not load baseline: {e}")

        return False

    def save_baseline(self, processes: Dict[str, Any], filename: str) -> str:
        """Save current process signatures as baseline."""
        baseline_processes = set()
        for proc in processes.values():
            # Create signature: name + path (normalized)
            name = proc.name.lower()
            path = (proc.exe_path or "").lower().replace("\\", "/")
            signature = f"{name}|{path}"
            baseline_processes.add(signature)

        data = {
            'timestamp': datetime.now().isoformat(),
            'baseline_processes': sorted(list(baseline_processes)),
            'process_count': len(processes)
        }

        filepath = os.path.join(config.OUTPUT_DIRECTORY, filename)
        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

        logger.info(f"Saved baseline with {len(baseline_processes)} process signatures")
        return filepath

    def detect_unknown_process(self, process_name: str, exe_path: str) -> bool:
        """Detect processes not in baseline."""
        if not self.baseline_processes:
            return False

        name = process_name.lower()
        path = (exe_path or "").lower().replace("\\", "/")
        signature = f"{name}|{path}"

        return signature not in self.baseline_processes

    def train_model(self, training_data: List[np.ndarray]) -> bool:
        """Train the Isolation Forest model."""
        if len(training_data) < 10:
            logger.warning("Insufficient training data for ML model")
            return False

        try:
            # Convert to numpy array
            X = np.array(training_data)

            # Scale features
            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(X)

            # Train Isolation Forest
            self.model = IsolationForest(
                contamination=self.contamination,
                random_state=self.random_state,
                n_estimators=100
            )
            self.model.fit(X_scaled)
            self.is_trained = True

            logger.info(f"Trained ML model on {len(training_data)} samples")
            return True

        except Exception as e:
            logger.error(f"Failed to train ML model: {e}")
            return False

    def predict_anomaly(self, features: np.ndarray) -> Tuple[bool, float]:
        """Predict if features represent an anomaly."""
        if not self.is_trained or self.model is None or self.scaler is None:
            return False, 0.0

        try:
            # Scale features
            features_scaled = self.scaler.transform(features.reshape(1, -1))

            # Predict anomaly score (-1 for anomaly, 1 for normal)
            prediction = self.model.predict(features_scaled)[0]
            anomaly_score = self.model.decision_function(features_scaled)[0]

            # Convert to boolean (anomaly = True)
            is_anomaly = prediction == -1

            return is_anomaly, float(anomaly_score)

        except Exception as e:
            logger.error(f"Failed to predict anomaly: {e}")
            return False, 0.0


class BehaviorAnalyzer:
    """Analyzes process behavior over time for anomaly detection."""

    def __init__(self):
        self.process_metrics: Dict[int, ProcessMetrics] = {}
        self.ml_detector = MLAnomalyDetector()
        self.training_data: List[np.ndarray] = []
        self.is_baseline_mode = False

    def update_process_metrics(self, pid: int, name: str, cpu_percent: float,
                             memory_rss: int, thread_count: int):
        """Update metrics for a process."""
        if pid not in self.process_metrics:
            self.process_metrics[pid] = ProcessMetrics(pid, name)

        self.process_metrics[pid].add_measurement(cpu_percent, memory_rss, thread_count)

        # Calculate baselines periodically
        if len(self.process_metrics[pid].cpu_history) % 10 == 0:
            self.process_metrics[pid].calculate_baselines()

    def detect_anomalies(self) -> List[Dict[str, Any]]:
        """Detect behavioral anomalies across all tracked processes."""
        anomalies = []

        for pid, metrics in self.process_metrics.items():
            # Get current values
            if not metrics.cpu_history or not metrics.memory_history:
                continue

            current_cpu = metrics.cpu_history[-1]
            current_memory = metrics.memory_history[-1]
            current_threads = metrics.thread_count_history[-1]

            # CPU spike detection
            if metrics.detect_cpu_spike(current_cpu):
                anomalies.append({
                    'type': 'CPU Usage Spike',
                    'severity': config.SEVERITY_HIGH,
                    'risk_score': config.RISK_SCORES[config.SEVERITY_HIGH],
                    'timestamp': datetime.now(),
                    'process_name': metrics.name,
                    'pid': pid,
                    'cpu_percent': current_cpu,
                    'baseline_cpu_mean': metrics.baseline_cpu_mean,
                    'reason': f'CPU usage {current_cpu:.1f}% exceeds baseline mean by >3σ',
                    'description': f'Unusual CPU spike detected for {metrics.name} (PID: {pid})'
                })

            # Memory leak detection
            if metrics.detect_memory_leak(current_memory):
                memory_mb = current_memory / (1024 * 1024)
                anomalies.append({
                    'type': 'Potential Memory Leak',
                    'severity': config.SEVERITY_MEDIUM,
                    'risk_score': config.RISK_SCORES[config.SEVERITY_MEDIUM],
                    'timestamp': datetime.now(),
                    'process_name': metrics.name,
                    'pid': pid,
                    'memory_mb': memory_mb,
                    'reason': 'Memory usage trending upward with increasing consumption pattern',
                    'description': f'Potential memory leak detected in {metrics.name} (PID: {pid})'
                })

            # ML-based anomaly detection
            if self.ml_detector.is_trained:
                features = metrics.get_features()
                if len(features) > 0:
                    is_anomaly, anomaly_score = self.ml_detector.predict_anomaly(features)
                    if is_anomaly:
                        anomalies.append({
                            'type': 'ML-Detected Behavioral Anomaly',
                            'severity': config.SEVERITY_MEDIUM,
                            'risk_score': config.RISK_SCORES[config.SEVERITY_MEDIUM],
                            'timestamp': datetime.now(),
                            'process_name': metrics.name,
                            'pid': pid,
                            'anomaly_score': anomaly_score,
                            'reason': f'Machine learning model detected anomalous behavior (score: {anomaly_score:.3f})',
                            'description': f'ML anomaly detected in {metrics.name} behavior patterns'
                        })

        return anomalies

    def collect_training_data(self):
        """Collect training data from current process metrics."""
        for metrics in self.process_metrics.values():
            features = metrics.get_features()
            if len(features) > 0:
                self.training_data.append(features)

    def train_ml_model(self) -> bool:
        """Train the ML model with collected data."""
        if len(self.training_data) < 20:
            logger.warning("Insufficient training data for ML model")
            return False

        success = self.ml_detector.train_model(self.training_data)
        if success:
            self.training_data = []  # Clear after training
        return success

    def detect_unknown_processes(self, current_processes: Dict[int, Any]) -> List[Dict[str, Any]]:
        """Detect processes not present in baseline."""
        anomalies = []

        for pid, proc in current_processes.items():
            if self.ml_detector.detect_unknown_process(proc.name, proc.exe_path):
                anomalies.append({
                    'type': 'Unknown Process Signature',
                    'severity': config.SEVERITY_MEDIUM,
                    'risk_score': config.RISK_SCORES[config.SEVERITY_MEDIUM],
                    'timestamp': datetime.now(),
                    'process_name': proc.name,
                    'pid': pid,
                    'path': proc.exe_path or 'N/A',
                    'reason': 'Process signature not found in baseline',
                    'description': f'Unknown process detected: {proc.name} @ {proc.exe_path or "N/A"}'
                })

        return anomalies

    def cleanup_old_metrics(self, max_age_hours: int = config.METRIC_CLEANUP_AGE_HOURS):
        """Remove metrics for processes that haven't been seen recently."""
        cutoff = datetime.now() - timedelta(hours=max_age_hours)
        to_remove = []

        for pid, metrics in self.process_metrics.items():
            if metrics.timestamps and metrics.timestamps[-1] < cutoff:
                to_remove.append(pid)

        for pid in to_remove:
            del self.process_metrics[pid]

        if to_remove:
            logger.info(f"Cleaned up metrics for {len(to_remove)} stale processes")