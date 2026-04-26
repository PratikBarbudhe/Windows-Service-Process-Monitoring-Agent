"""
Enhanced Streamlit Dashboard with Interactive Charts

Features:
- Real-time CPU and memory usage charts
- Top processes by CPU and memory
- Process-specific timeline charts
- System statistics and trends
- Responsive layout for presentations

Run:
    streamlit run dashboard_streamlit_enhanced.py
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta
from glob import glob
from typing import Any, Dict, List

import pandas as pd
import streamlit as st

import config
from metrics_collector import MetricsCollector

# Page configuration
st.set_page_config(
    page_title="Windows Monitoring Dashboard",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom theme
st.markdown(
    """
    <style>
        .main { padding: 2rem; }
        .metric-card { 
            background-color: #f0f2f6;
            padding: 1rem;
            border-radius: 0.5rem;
            margin: 0.5rem 0;
        }
        h1 { color: #1f77b4; border-bottom: 3px solid #1f77b4; padding-bottom: 0.5rem; }
        h2 { color: #1f77b4; margin-top: 1.5rem; }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource
def get_metrics_collector():
    """Get or create metrics collector instance."""
    return MetricsCollector()


def load_alerts_json() -> Dict[str, Any]:
    """Load latest alerts JSON file."""
    log_dir = config.LOG_DIRECTORY
    pattern = os.path.join(log_dir, "alerts_*.json")
    files = sorted(glob(pattern))
    if not files:
        return {}
    
    try:
        with open(files[-1], encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        st.error(f"Error loading alerts: {e}")
        return {}


def main():
    """Main dashboard function."""
    
    # Header
    st.title("🖥️ Windows Service Monitoring Dashboard")
    st.markdown("Real-time system metrics and process monitoring with interactive visualizations")
    
    # Sidebar configuration
    st.sidebar.header("⚙️ Dashboard Settings")
    
    time_range = st.sidebar.selectbox(
        "Time Range",
        ["1 hour", "6 hours", "24 hours"],
        index=0
    )
    
    hours_map = {"1 hour": 1, "6 hours": 6, "24 hours": 24}
    hours = hours_map[time_range]
    
    refresh_interval = st.sidebar.slider(
        "Auto-refresh interval (seconds)",
        min_value=5,
        max_value=60,
        value=30,
        step=5
    )
    
    # Get metrics
    collector = get_metrics_collector()
    
    # Collect fresh snapshot
    current_snapshot = collector.collect_snapshot()
    
    if current_snapshot is None:
        st.error("Failed to collect metrics")
        return
    
    # ========================================================================
    # Section 1: System Overview
    # ========================================================================
    st.header("📊 System Overview")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "CPU Usage",
            f"{current_snapshot.system.cpu_percent:.1f}%",
            delta="System-wide"
        )
    
    with col2:
        st.metric(
            "Memory Usage",
            f"{current_snapshot.system.memory_percent:.1f}%",
            delta=f"{current_snapshot.system.memory_available_mb:.0f} MB free"
        )
    
    with col3:
        st.metric(
            "Running Processes",
            current_snapshot.system.process_count,
            delta="Active processes"
        )
    
    with col4:
        st.metric(
            "Active Threads",
            current_snapshot.system.thread_count,
            delta="System threads"
        )
    
    # ========================================================================
    # Section 2: CPU Usage Timeline
    # ========================================================================
    st.header("📈 CPU Usage Timeline")
    
    cpu_timeline = collector.get_cpu_usage_timeline(hours=hours)
    
    if cpu_timeline:
        df_cpu = pd.DataFrame(cpu_timeline)
        
        # Parse timestamp for better display
        df_cpu['timestamp'] = pd.to_datetime(df_cpu['timestamp'])
        df_cpu = df_cpu.sort_values('timestamp')
        
        # Create chart
        st.line_chart(
            df_cpu.set_index('timestamp')[['system_cpu']],
            height=400,
            use_container_width=True,
            x_label="Time",
            y_label="CPU Usage (%)"
        )
        
        # Statistics
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Avg CPU", f"{df_cpu['system_cpu'].mean():.1f}%")
        with col2:
            st.metric("Max CPU", f"{df_cpu['system_cpu'].max():.1f}%")
        with col3:
            st.metric("Min CPU", f"{df_cpu['system_cpu'].min():.1f}%")
    else:
        st.info("No CPU metrics available yet. Metrics are collected periodically.")
    
    # ========================================================================
    # Section 3: Memory Usage Timeline
    # ========================================================================
    st.header("💾 Memory Usage Timeline")
    
    memory_timeline = collector.get_memory_usage_timeline(hours=hours)
    
    if memory_timeline:
        df_memory = pd.DataFrame(memory_timeline)
        df_memory['timestamp'] = pd.to_datetime(df_memory['timestamp'])
        df_memory = df_memory.sort_values('timestamp')
        
        # Create chart
        st.area_chart(
            df_memory.set_index('timestamp')[['system_memory_percent']],
            height=400,
            use_container_width=True,
            x_label="Time",
            y_label="Memory Usage (%)"
        )
        
        # Statistics
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Avg Memory", f"{df_memory['system_memory_percent'].mean():.1f}%")
        with col2:
            st.metric("Max Memory", f"{df_memory['system_memory_percent'].max():.1f}%")
        with col3:
            st.metric("Min Memory", f"{df_memory['system_memory_percent'].min():.1f}%")
    else:
        st.info("No memory metrics available yet.")
    
    # ========================================================================
    # Section 4: Top Processes
    # ========================================================================
    st.header("🔝 Top Processes")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Top Processes by CPU")
        top_cpu = collector.get_top_processes_by_cpu(hours=hours, limit=10)
        
        if top_cpu:
            df_cpu_procs = pd.DataFrame(top_cpu)
            
            # Bar chart
            st.bar_chart(
                df_cpu_procs.set_index('name')['avg_cpu'],
                height=400,
                use_container_width=True,
                x_label="Process",
                y_label="Avg CPU (%)"
            )
            
            # Table
            st.dataframe(
                df_cpu_procs[['name', 'avg_cpu', 'max_cpu', 'samples']].rename(
                    columns={
                        'name': 'Process',
                        'avg_cpu': 'Avg CPU %',
                        'max_cpu': 'Max CPU %',
                        'samples': 'Samples'
                    }
                ),
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("No process metrics available yet.")
    
    with col2:
        st.subheader("Top Processes by Memory")
        top_memory = collector.get_top_processes_by_memory(hours=hours, limit=10)
        
        if top_memory:
            df_mem_procs = pd.DataFrame(top_memory)
            
            # Bar chart
            st.bar_chart(
                df_mem_procs.set_index('name')['avg_memory_mb'],
                height=400,
                use_container_width=True,
                x_label="Process",
                y_label="Avg Memory (MB)"
            )
            
            # Table
            st.dataframe(
                df_mem_procs[['name', 'avg_memory_mb', 'max_memory_mb', 'samples']].rename(
                    columns={
                        'name': 'Process',
                        'avg_memory_mb': 'Avg Memory MB',
                        'max_memory_mb': 'Max Memory MB',
                        'samples': 'Samples'
                    }
                ),
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("No process metrics available yet.")
    
    # ========================================================================
    # Section 5: Process Details
    # ========================================================================
    st.header("🔍 Process Details")
    
    # Get unique process names
    all_processes = set()
    for proc in current_snapshot.processes:
        all_processes.add(proc.name)
    
    if all_processes:
        selected_process = st.selectbox(
            "Select process to view details:",
            sorted(all_processes)
        )
        
        if selected_process:
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader(f"{selected_process} - CPU Usage")
                process_cpu_timeline = collector.get_process_cpu_timeline(
                    selected_process, hours=hours
                )
                
                if process_cpu_timeline:
                    df_proc_cpu = pd.DataFrame(process_cpu_timeline)
                    df_proc_cpu['timestamp'] = pd.to_datetime(df_proc_cpu['timestamp'])
                    
                    st.line_chart(
                        df_proc_cpu.set_index('timestamp')[['cpu']],
                        height=350,
                        use_container_width=True
                    )
            
            with col2:
                st.subheader(f"{selected_process} - Memory Usage")
                process_mem_timeline = collector.get_process_memory_timeline(
                    selected_process, hours=hours
                )
                
                if process_mem_timeline:
                    df_proc_mem = pd.DataFrame(process_mem_timeline)
                    df_proc_mem['timestamp'] = pd.to_datetime(df_proc_mem['timestamp'])
                    
                    st.area_chart(
                        df_proc_mem.set_index('timestamp')[['memory_mb']],
                        height=350,
                        use_container_width=True
                    )
            
            # Current process info
            st.subheader("Current Process Information")
            current_procs = [p for p in current_snapshot.processes if p.name == selected_process]
            
            if current_procs:
                process_data = []
                for proc in current_procs:
                    process_data.append({
                        'PID': proc.pid,
                        'Name': proc.name,
                        'CPU %': f"{proc.cpu_percent:.1f}",
                        'Memory MB': f"{proc.memory_mb:.1f}",
                        'Threads': proc.num_threads,
                        'Handles': proc.handles
                    })
                
                st.dataframe(
                    pd.DataFrame(process_data),
                    use_container_width=True,
                    hide_index=True
                )
    else:
        st.info("No processes available to display.")
    
    # ========================================================================
    # Section 6: Alerts
    # ========================================================================
    st.header("⚠️ Recent Alerts")
    
    alerts_data = load_alerts_json()
    
    if alerts_data:
        total_alerts = alerts_data.get('total_alerts', 0)
        severity_breakdown = alerts_data.get('severity_breakdown', {})
        
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            st.metric("Total Alerts", total_alerts)
        with col2:
            st.metric("Critical", severity_breakdown.get('CRITICAL', 0), delta="🔴")
        with col3:
            st.metric("High", severity_breakdown.get('HIGH', 0), delta="🟠")
        with col4:
            st.metric("Medium", severity_breakdown.get('MEDIUM', 0), delta="🟡")
        with col5:
            st.metric("Low", severity_breakdown.get('LOW', 0), delta="🟢")
        
        # Alert table
        alerts_list = alerts_data.get('alerts', [])
        if alerts_list:
            df_alerts = pd.DataFrame([
                {
                    'Time': alert.get('timestamp', 'N/A')[-19:],  # HH:MM:SS
                    'Severity': alert.get('severity', 'N/A'),
                    'Type': alert.get('type', 'N/A'),
                    'Process': alert.get('process_name', alert.get('child_name', 'N/A')),
                    'Description': alert.get('description', alert.get('reason', 'N/A'))[:50]
                }
                for alert in alerts_list[:20]  # Show latest 20
            ])
            
            st.dataframe(
                df_alerts,
                use_container_width=True,
                hide_index=True
            )
    else:
        st.info("No alerts available. Run monitor_agent.py to generate alerts.")
    
    # ========================================================================
    # Section 7: Summary Statistics
    # ========================================================================
    st.header("📋 Summary Statistics")
    
    summary = collector.get_summary_stats(hours=hours)
    
    if summary:
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Unique Processes", summary.get('unique_processes', 0))
            st.metric("Total Snapshots", summary.get('snapshot_count', 0))
        
        with col2:
            st.metric("Avg CPU %", f"{summary.get('cpu_avg', 0):.1f}")
            st.metric("Max CPU %", f"{summary.get('cpu_max', 0):.1f}")
        
        with col3:
            st.metric("Avg Memory %", f"{summary.get('memory_avg_percent', 0):.1f}")
            st.metric("Max Memory %", f"{summary.get('memory_max_percent', 0):.1f}")
    
    # Auto-refresh
    st.sidebar.markdown("---")
    st.sidebar.info(f"🔄 Dashboard auto-refreshes every {refresh_interval} seconds")
    
    # Footer
    st.markdown("---")
    st.caption(
        f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
        "Windows Service Monitoring Agent"
    )


if __name__ == "__main__":
    main()
