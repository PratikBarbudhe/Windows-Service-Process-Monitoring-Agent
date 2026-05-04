from __future__ import annotations

import json
import platform
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd
import plotly.express as px
import psutil
import requests
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.config import settings
from app.monitoring import MonitoringAgent

SEVERITY_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#eab308",
    "LOW": "#3b82f6",
    "INFO": "#22c55e",
}


def inject_css() -> None:
    st.markdown(
        """
        <style>
            .stApp {
                background: #0a0f1f;
                color: #e5e7eb;
            }
            .soc-header {
                background: linear-gradient(90deg, #111827 0%, #0b1220 100%);
                border: 1px solid #1f2937;
                border-radius: 14px;
                padding: 16px 20px;
                margin-bottom: 14px;
            }
            .soc-title {
                color: #e5e7eb;
                font-size: 1.7rem;
                font-weight: 700;
                margin: 0;
            }
            .soc-subtitle {
                color: #9ca3af;
                margin-top: 6px;
                margin-bottom: 0;
                font-size: 0.9rem;
            }
            .status-pill {
                display: inline-block;
                padding: 6px 12px;
                border-radius: 999px;
                font-weight: 700;
                font-size: 0.8rem;
                border: 1px solid rgba(255,255,255,0.12);
            }
            .metric-card {
                background: #111827;
                border: 1px solid #1f2937;
                border-radius: 14px;
                padding: 14px 16px;
                min-height: 108px;
                box-shadow: 0 8px 24px rgba(0,0,0,0.2);
                transition: transform .2s ease, border-color .2s ease;
                margin-bottom: 10px;
            }
            .metric-card:hover {
                transform: translateY(-2px);
                border-color: #39ff14;
            }
            .metric-label {
                color: #93a3b8;
                font-size: .85rem;
                margin: 0 0 8px 0;
            }
            .metric-value {
                color: #e5e7eb;
                font-size: 1.65rem;
                font-weight: 700;
                margin: 0;
            }
            .metric-accent {
                color: #39ff14;
                font-size: .8rem;
                margin-top: 8px;
            }
            div.stButton > button {
                background-color: #111827;
                color: #e5e7eb;
                border: 1px solid #2c3e50;
                border-radius: 10px;
                padding: .5rem .9rem;
                font-weight: 600;
            }
            div.stButton > button:hover {
                border-color: #39ff14;
                color: #39ff14;
            }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _load_latest_payload() -> dict:
    latest_file = settings.log_dir / "alerts_latest.json"
    if not latest_file.exists():
        return {}
    return json.loads(latest_file.read_text(encoding="utf-8"))


def _api_headers(api_token: str) -> dict[str, str]:
    return {"x-api-token": api_token}


def _fetch_api_data(api_base_url: str, api_token: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    base = api_base_url.rstrip("/")
    processes_resp = requests.get(
        f"{base}/processes",
        headers=_api_headers(api_token),
        timeout=15,
    )
    processes_resp.raise_for_status()
    alerts_resp = requests.get(
        f"{base}/alerts",
        headers=_api_headers(api_token),
        timeout=15,
    )
    alerts_resp.raise_for_status()

    processes = processes_resp.json().get("processes", [])
    alerts = alerts_resp.json().get("alerts", [])
    return processes, alerts


def _export_alerts(alerts: list[dict[str, Any]]) -> str | None:
    if not alerts:
        return None
    settings.report_dir.mkdir(parents=True, exist_ok=True)
    out = settings.report_dir / f"alerts_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    pd.DataFrame(alerts).to_csv(out, index=False)
    return str(out)


def _status_from_alerts(alerts: list[dict[str, Any]]) -> tuple[str, str]:
    severities = {str(item.get("severity", "INFO")).upper() for item in alerts}
    if "CRITICAL" in severities:
        return "CRITICAL", "#ef4444"
    if "HIGH" in severities:
        return "WARNING", "#eab308"
    return "RUNNING", "#22c55e"


def render_header(last_updated: str, status_text: str, status_color: str) -> None:
    left, right = st.columns([5, 1.2])
    with left:
        st.markdown(
            f"""
            <div class="soc-header">
              <h1 class="soc-title">Windows Monitoring Agent</h1>
              <p class="soc-subtitle">SOC Dashboard | Last updated: {last_updated}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with right:
        st.markdown(
            f"""
            <div style="margin-top:18px; text-align:right;">
                <span class="status-pill" style="background:{status_color}22;color:{status_color};">
                    {status_text}
                </span>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_sidebar() -> tuple[str, bool, int, str, str, str]:
    st.sidebar.markdown("## Navigation")
    page = st.sidebar.radio(
        "Section",
        options=["Dashboard", "Processes", "Alerts", "Services"],
        label_visibility="collapsed",
    )
    st.sidebar.markdown("---")
    data_source = st.sidebar.radio("Data source", ["Local Logs", "Remote API"], index=0)
    api_base_url = st.sidebar.text_input(
        "API Base URL",
        value=settings.dashboard_api_base_url,
        disabled=data_source != "Remote API",
    )
    api_token = st.sidebar.text_input(
        "API Token",
        value=settings.dashboard_api_token,
        type="password",
        disabled=data_source != "Remote API",
    )
    st.sidebar.markdown("---")
    auto_refresh = st.sidebar.toggle("Auto refresh", value=True)
    refresh_interval = st.sidebar.slider(
        "Refresh every (minutes)",
        min_value=5,
        max_value=60,
        value=5,
    )
    st.sidebar.caption("Theme: Dark SOC")
    return page, auto_refresh, refresh_interval, data_source, api_base_url, api_token


def render_toolbar(
    alerts: list[dict[str, Any]],
    data_source: str,
    api_base_url: str,
    api_token: str,
) -> None:
    c1, c2, c3 = st.columns([1, 1, 1.2])
    if c1.button("Run Scan", icon=":material/play_arrow:", use_container_width=True):
        with st.spinner("Running scan..."):
            try:
                if data_source == "Remote API":
                    response = requests.post(
                        f"{api_base_url.rstrip('/')}/scan",
                        headers=_api_headers(api_token),
                        timeout=30,
                    )
                    response.raise_for_status()
                else:
                    MonitoringAgent().run_scan()
                st.success("Scan completed.")
            except Exception as exc:  # noqa: BLE001
                st.error(f"Scan failed: {exc}")
            st.rerun()
    if c2.button("Reload Logs", icon=":material/refresh:", use_container_width=True):
        st.info("Logs reloaded.")
        st.rerun()
    if c3.button("Export Reports", icon=":material/download:", use_container_width=True):
        exported = _export_alerts(alerts)
        if exported:
            st.success(f"Exported: {exported}")
        else:
            st.warning("No alerts available to export.")


def render_empty_state() -> None:
    st.warning(
        "No scan results found yet. Click 'Run Scan' to generate telemetry, "
        "or run `python main.py` on the same environment as this dashboard."
    )


def _metric_card(label: str, value: int, icon: str, accent: str = "") -> None:
    st.markdown(
        f"""
        <div class="metric-card">
            <p class="metric-label">{icon} {label}</p>
            <p class="metric-value">{value}</p>
            <p class="metric-accent">{accent}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_metrics(processes: list[dict[str, Any]], alerts: list[dict[str, Any]]) -> None:
    sev = pd.Series([str(item.get("severity", "INFO")).upper() for item in alerts])
    counts = sev.value_counts().to_dict()

    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        _metric_card("Total Processes", len(processes), "🖥️", "Live process inventory")
    with c2:
        _metric_card("Total Alerts", len(alerts), "🚨", "Detected in latest scan")
    with c3:
        _metric_card("Critical", int(counts.get("CRITICAL", 0)), "🔴", "Immediate action")
    with c4:
        _metric_card("High", int(counts.get("HIGH", 0)), "🟠", "Investigate now")
    with c5:
        _metric_card("Medium", int(counts.get("MEDIUM", 0)), "🟡", "Needs review")


def render_charts(alerts: list[dict[str, Any]]) -> None:
    if not alerts:
        st.info("No alert data available for charting.")
        return

    df = pd.DataFrame(alerts)
    if "severity" not in df:
        df["severity"] = "INFO"
    df["severity"] = df["severity"].astype(str).str.upper()

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    sev_counts = (
        df["severity"]
        .value_counts()
        .reindex(severity_order, fill_value=0)
        .reset_index()
    )
    sev_counts.columns = ["severity", "count"]

    if "created_at" in df.columns:
        df["created_at"] = pd.to_datetime(df["created_at"], errors="coerce")
    else:
        df["created_at"] = pd.Timestamp.utcnow()
    timeline = (
        df.dropna(subset=["created_at"])
        .set_index("created_at")
        .resample("1min")
        .size()
        .reset_index(name="alerts")
    )

    c1, c2 = st.columns(2)
    with c1:
        fig_bar = px.bar(
            sev_counts,
            x="severity",
            y="count",
            color="severity",
            color_discrete_map=SEVERITY_COLORS,
            title="Severity Distribution",
            template="plotly_dark",
        )
        fig_bar.update_layout(height=360, legend_title_text="")
        st.plotly_chart(fig_bar, use_container_width=True)
    with c2:
        fig_line = px.line(
            timeline,
            x="created_at",
            y="alerts",
            title="Alerts Over Time",
            template="plotly_dark",
            markers=True,
        )
        fig_line.update_layout(height=360, xaxis_title="Time", yaxis_title="Alert Count")
        st.plotly_chart(fig_line, use_container_width=True)


def render_alerts(alerts: list[dict[str, Any]]) -> None:
    st.subheader("Live Alerts")
    if not alerts:
        st.success("No active alerts in the latest scan.")
        return

    severity_filter = st.selectbox(
        "Filter by severity",
        ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        index=0,
    )

    visible_alerts = alerts
    if severity_filter != "ALL":
        visible_alerts = [
            item for item in alerts if str(item.get("severity", "")).upper() == severity_filter
        ]

    for alert in visible_alerts[:8]:
        sev = str(alert.get("severity", "INFO")).upper()
        msg = (
            f"{sev} | {alert.get('type', 'Alert')} | "
            f"{alert.get('message', 'No description')}"
        )
        if sev == "CRITICAL":
            st.error(msg)
        elif sev in {"HIGH", "MEDIUM"}:
            st.warning(msg)
        else:
            st.info(msg)

    st.dataframe(pd.DataFrame(visible_alerts), use_container_width=True, hide_index=True)


def _sample_live_processes(sample_seconds: float = 1.0) -> list[dict[str, Any]]:
    procs = list(psutil.process_iter(["pid", "name", "username", "exe", "memory_info"]))

    for proc in procs:
        try:
            proc.cpu_percent(interval=None)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue

    time.sleep(max(sample_seconds, 0.2))

    rows: list[dict[str, Any]] = []
    for proc in procs:
        try:
            mem_info = proc.info.get("memory_info")
            memory_mb = round((mem_info.rss / 1024 / 1024) if mem_info else 0.0, 2)
            rows.append(
                {
                    "pid": proc.info.get("pid"),
                    "name": proc.info.get("name") or "unknown",
                    "username": proc.info.get("username"),
                    "exe": proc.info.get("exe"),
                    "cpu_percent": round(float(proc.cpu_percent(interval=None)), 2),
                    "memory_mb": memory_mb,
                }
            )
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
    return rows


def render_processes(processes: list[dict[str, Any]], allow_live_sampling: bool = True) -> None:
    st.subheader("Process Inventory")

    c1, c2 = st.columns([1.4, 2.6])
    with c1:
        live_mode = st.toggle(
            "Use live process sampling",
            value=allow_live_sampling,
            disabled=not allow_live_sampling,
        )
    with c2:
        st.caption("Live sampling gives more accurate CPU usage than stale log snapshots.")

    if live_mode and allow_live_sampling:
        with st.spinner("Sampling process CPU usage..."):
            processes = _sample_live_processes(sample_seconds=1.0)

    if not processes:
        st.info("No process data available.")
        return

    df = pd.DataFrame(processes)
    if {"cpu_percent", "memory_mb"}.issubset(df.columns):
        df = df.sort_values(by=["cpu_percent", "memory_mb"], ascending=False)
    if platform.system() != "Windows":
        st.caption(
            "Running in a Linux container (Streamlit Cloud), so you only see container processes "
            "instead of full Windows host processes."
        )
    st.caption(f"Total visible processes in current runtime: {len(df)}")
    st.dataframe(df, use_container_width=True, hide_index=True)


def render_services() -> None:
    st.subheader("Services")
    st.info(
        "Service-specific telemetry is not present in `alerts_latest.json` yet. "
        "Integrate service scan payloads here when available."
    )


def main() -> None:
    st.set_page_config(page_title="Windows Monitoring Agent", layout="wide", initial_sidebar_state="expanded")
    inject_css()

    page, auto_refresh, refresh_interval, data_source, api_base_url, api_token = render_sidebar()

    payload: dict[str, Any] = {}
    processes: list[dict[str, Any]] = []
    alerts: list[dict[str, Any]] = []
    source_error = ""

    if data_source == "Remote API":
        try:
            processes, alerts = _fetch_api_data(api_base_url, api_token)
            payload = {"processes": processes, "alerts": alerts}
            st.caption(f"Connected to API: {api_base_url}")
        except Exception as exc:  # noqa: BLE001
            source_error = str(exc)
            st.error(f"API connection failed: {source_error}")
    else:
        payload = _load_latest_payload()
        processes = payload.get("processes", []) if payload else []
        alerts = payload.get("alerts", []) if payload else []
    status_text, status_color = _status_from_alerts(alerts)
    updated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    render_header(updated_at, status_text, status_color)
    render_toolbar(alerts, data_source, api_base_url, api_token)
    st.markdown("")

    if not payload:
        render_empty_state()

    if page == "Dashboard":
        render_metrics(processes, alerts)
        render_charts(alerts)
        render_alerts(alerts)
    elif page == "Processes":
        render_processes(processes, allow_live_sampling=(data_source == "Local Logs"))
    elif page == "Alerts":
        render_alerts(alerts)
        render_charts(alerts)
    else:
        render_services()

    if auto_refresh:
        with st.spinner(f"Auto refresh in {refresh_interval} minute(s)..."):
            time.sleep(refresh_interval * 60)
        st.rerun()


if __name__ == "__main__":
    main()
