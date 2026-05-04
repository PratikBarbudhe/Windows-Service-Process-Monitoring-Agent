from __future__ import annotations

import json

import streamlit as st

from app.config import settings


def _load_latest_payload() -> dict:
    latest_file = settings.log_dir / "alerts_latest.json"
    if not latest_file.exists():
        return {}
    return json.loads(latest_file.read_text(encoding="utf-8"))


def main() -> None:
    st.set_page_config(page_title="Monitoring Dashboard", layout="wide")
    st.title("Windows Monitoring Dashboard")

    payload = _load_latest_payload()
    if not payload:
        st.warning("No scan results found. Run `python main.py` first.")
        return

    processes = payload.get("processes", [])
    alerts = payload.get("alerts", [])

    st.metric("Processes", len(processes))
    st.metric("Alerts", len(alerts))
    st.subheader("Latest alerts")
    st.dataframe(alerts, use_container_width=True, hide_index=True)


if __name__ == "__main__":
    main()

