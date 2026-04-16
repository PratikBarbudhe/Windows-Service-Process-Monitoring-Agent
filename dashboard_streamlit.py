"""
Optional Streamlit dashboard for quick visualization of the latest JSON exports in ./logs.

Run (from repo root):
    streamlit run dashboard_streamlit.py
"""

from __future__ import annotations

import json
import os
from glob import glob
from typing import Any, Dict, List

import config
import streamlit as st

LOG_DIR = config.LOG_DIRECTORY


def _load_latest_alerts_json() -> Dict[str, Any]:
    pattern = os.path.join(LOG_DIR, "alerts_*.json")
    files = sorted(glob(pattern))
    if not files:
        return {}
    latest = files[-1]
    with open(latest, encoding="utf-8") as f:
        data: Dict[str, Any] = json.load(f)
    data["_source_file"] = latest
    return data


def main() -> None:
    st.set_page_config(page_title="Windows Monitoring Agent", layout="wide")
    st.title("Windows Service & Process Monitoring Agent")
    st.caption("Reads the most recent alerts JSON from the logs directory.")

    data = _load_latest_alerts_json()
    if not data:
        st.warning(f"No alerts_*.json found under {LOG_DIR}. Run monitor_agent.py first.")
        return

    st.success(f"Loaded: {data.get('_source_file')}")
    st.metric("Total alerts", data.get("total_alerts", 0))

    breakdown = data.get("severity_breakdown") or {}
    cols = st.columns(5)
    labels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    for col, label in zip(cols, labels):
        col.metric(label, breakdown.get(label, 0))

    alerts: List[Dict[str, Any]] = data.get("alerts") or []
    st.subheader("Alerts table")
    st.dataframe(
        [
            {
                "severity": a.get("severity"),
                "risk": a.get("risk_score"),
                "type": a.get("type"),
                "reason": a.get("reason") or a.get("description"),
                "process": a.get("process_name") or a.get("child_name"),
                "service": a.get("service_name"),
                "path": a.get("path") or a.get("child_path"),
            }
            for a in alerts
        ],
        use_container_width=True,
        hide_index=True,
    )


if __name__ == "__main__":
    main()
