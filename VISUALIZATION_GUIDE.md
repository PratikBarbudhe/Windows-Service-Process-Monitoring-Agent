# Visualization Guide - Charts and Real-Time Monitoring

## Overview

The Windows Service Monitoring Agent now includes powerful visualization capabilities with interactive charts for CPU usage, memory consumption, and process monitoring. Multiple dashboard options are available for different use cases.

## 📊 Visualization Components

### 1. Metrics Collector (`metrics_collector.py`)

Core module that collects and stores system metrics over time.

**Features:**
- Automatic system-wide metrics collection
- Per-process CPU and memory tracking
- Historical data storage (7-day retention)
- Time-series data for charting
- Summary statistics and analytics

**Key Methods:**
- `collect_snapshot()` - Collect current metrics
- `get_cpu_usage_timeline()` - CPU history for charts
- `get_memory_usage_timeline()` - Memory history
- `get_top_processes_by_cpu()` - Ranked process data
- `get_top_processes_by_memory()` - Memory rankings
- `get_process_cpu_timeline()` - Single process tracking
- `get_process_memory_timeline()` - Single process memory
- `get_summary_stats()` - Aggregated statistics

### 2. Streamlit Enhanced Dashboard (`dashboard_streamlit_enhanced.py`)

Modern, responsive web dashboard using Streamlit and Plotly.

**Sections:**
1. **System Overview** - Real-time metrics (CPU, Memory, Processes, Threads)
2. **CPU Timeline** - Interactive CPU usage chart with statistics
3. **Memory Timeline** - Memory usage area chart with trends
4. **Top Processes** - Bar charts for CPU and memory usage
5. **Process Details** - Drill-down into individual processes
6. **Alerts** - Recent alert history with severity breakdown
7. **Summary Statistics** - Aggregated metrics for time period

**Run:**
```bash
streamlit run dashboard_streamlit_enhanced.py
```

Access: `http://localhost:8501`

### 3. Interactive HTML Dashboard (`dashboard_interactive.html`)

Standalone HTML/JavaScript dashboard using Chart.js.

**Features:**
- 4 real-time charts (CPU timeline, Memory timeline, Top CPU, Top Memory)
- Metric cards for quick overview
- Configurable time ranges (1, 6, 24 hours)
- Auto-refresh capability (30s to 5m)
- JWT authentication
- Responsive design

**Chart Types:**
- Line chart: CPU over time
- Area chart: Memory over time
- Horizontal bar charts: Top processes

**Use:**
1. Open in browser: `file:///path/to/dashboard_interactive.html`
2. Or serve via HTTP for remote access
3. Configure API URL and credentials
4. Charts update automatically

### 4. REST API Chart Endpoints (`api_server.py`)

Backend endpoints providing chart data in JSON format.

**Endpoints:**

#### System Timelines
- `GET /api/charts/cpu-timeline?hours=24` - CPU usage over time
- `GET /api/charts/memory-timeline?hours=24` - Memory usage over time

#### Top Processes
- `GET /api/charts/top-processes-cpu?hours=24&limit=10` - Top 10 by CPU
- `GET /api/charts/top-processes-memory?hours=24&limit=10` - Top 10 by memory

#### Process Details
- `GET /api/charts/process-cpu/<name>?hours=24` - CPU timeline for process
- `GET /api/charts/process-memory/<name>?hours=24` - Memory timeline for process

#### Summary
- `GET /api/charts/metrics-summary?hours=24` - Aggregated statistics

All endpoints require JWT authentication.

**Response Format:**
```json
{
  "success": true,
  "data": {
    "timeline": [
      {"timestamp": "2026-04-26T10:30:00", "system_cpu": 25.5, ...},
      ...
    ],
    "count": 120,
    "timestamp": "2026-04-26T11:00:00"
  },
  "message": "Success"
}
```

## 🚀 Quick Start

### Option 1: Streamlit Dashboard (Recommended for Development)

**Install dependencies:**
```bash
pip install streamlit pandas plotly
```

**Run:**
```bash
streamlit run dashboard_streamlit_enhanced.py
```

**Access:** `http://localhost:8501`

**Advantages:**
- Interactive Plotly charts
- Built-in data tables
- Easy drill-down and filtering
- Real-time updates
- Process-specific analysis

### Option 2: Interactive HTML Dashboard (Best for Presentations)

**No installation needed!** Pure HTML/JavaScript.

**Use:**
1. Open `dashboard_interactive.html` in any web browser
2. Configure API server URL and credentials
3. Select time range and auto-refresh rate
4. View charts and metrics

**Advantages:**
- No dependencies
- Lightweight and fast
- Great for presentations
- Remote access via HTTP
- Professional Chart.js styling

### Option 3: Flask Admin Panel (Legacy)

Original admin panel with basic metrics display.

**Run:**
```bash
python admin_panel.py
```

**Access:** `http://localhost:5000`

## 📈 Chart Types and Use Cases

### CPU Usage Timeline
**Shows:** CPU percentage over time
**Use Case:** Identify performance issues, peak usage times
**Chart Type:** Line chart with area fill
**Data Points:** Hourly/minutely aggregates

### Memory Usage Timeline
**Shows:** Memory percentage and available memory over time
**Use Case:** Monitor memory leaks, capacity planning
**Chart Type:** Area chart
**Data Points:** Hourly/minutely aggregates

### Top Processes by CPU
**Shows:** Processes ranked by average CPU usage
**Use Case:** Identify resource hogs, optimization targets
**Chart Type:** Horizontal bar chart
**Data:** Top 10, with avg/max CPU percentages

### Top Processes by Memory
**Shows:** Processes ranked by memory consumption
**Use Case:** Find memory leaks, manage resources
**Chart Type:** Horizontal bar chart
**Data:** Top 10, with avg/max memory in MB

### Process-Specific Timeline
**Shows:** Individual process CPU/memory over time
**Use Case:** Debug specific process behavior
**Chart Type:** Line chart
**Data:** Aggregated from all instances of process

## 🔧 Configuration

### Metrics Collection

**Automatic Collection Interval:**
- Default: 5 minutes (300 seconds)
- Edit `metrics_collector.py` → `COLLECTION_INTERVAL`

**Data Retention:**
- Default: 7 days
- Edit `metrics_collector.py` → `METRICS_RETENTION_DAYS`

**Storage:**
- Location: `metrics/` directory
- Format: JSONL (one JSON object per line)
- File: `metrics_history.jsonl`

### Dashboard Configuration

**Streamlit:**
```bash
# Custom port
streamlit run dashboard_streamlit_enhanced.py --server.port 9000

# Disable file watcher
streamlit run dashboard_streamlit_enhanced.py --logger.level=debug

# Theme
streamlit run dashboard_streamlit_enhanced.py --theme.primaryColor="#667eea"
```

**HTML Dashboard:**
- Configure in modal on first load
- Settings saved to browser localStorage
- Change via: Settings → API Configuration

**API Server:**
```bash
# Custom port
export API_PORT=5002
python api_server.py

# Debug mode
export API_DEBUG=True
python api_server.py
```

## 📊 Example API Responses

### CPU Timeline
```json
{
  "success": true,
  "data": {
    "timeline": [
      {
        "timestamp": "2026-04-26T10:30:00+00:00",
        "system_cpu": 25.5,
        "process_count": 145
      }
    ],
    "hours": 1,
    "count": 12
  }
}
```

### Top Processes by CPU
```json
{
  "success": true,
  "data": {
    "processes": [
      {
        "name": "chrome.exe",
        "avg_cpu": 15.5,
        "max_cpu": 28.3,
        "samples": 120
      }
    ],
    "hours": 1,
    "limit": 10,
    "count": 8
  }
}
```

### Metrics Summary
```json
{
  "success": true,
  "data": {
    "summary": {
      "time_period_hours": 24,
      "snapshot_count": 288,
      "unique_processes": 145,
      "cpu_avg": 15.5,
      "cpu_max": 95.2,
      "cpu_min": 5.1,
      "memory_avg_percent": 45.3,
      "memory_max_percent": 78.5,
      "memory_min_percent": 38.2
    }
  }
}
```

## 🎨 Customization

### Streamlit Dashboard Customization

**Change colors:**
```python
# In dashboard_streamlit_enhanced.py
st.markdown("""
    <style>
        h1 { color: #FF6B6B; }
        .metric-card { background: #FFE66D; }
    </style>
""", unsafe_allow_html=True)
```

**Add custom charts:**
```python
# Add new section
st.header("Custom Analysis")

custom_data = collector.get_cpu_usage_timeline(hours=24)
df = pd.DataFrame(custom_data)
st.line_chart(df.set_index('timestamp'))
```

### HTML Dashboard Customization

**Change colors:**
```javascript
// Edit color scheme in styles
body { background: linear-gradient(135deg, #FF6B6B 0%, #764ba2 100%); }
.btn { background: #FF6B6B; }
```

**Add new metrics:**
```javascript
// In updateMetrics() function
document.getElementById('customMetric').textContent = custom_value;
```

**Modify chart options:**
```javascript
// In chart creation
options: {
    scales: {
        y: { beginAtZero: true, max: 100 }
    }
}
```

## 📱 Mobile Support

### Responsive Design
- HTML dashboard is fully responsive
- Adapts to mobile screens
- Touch-friendly controls
- Optimized chart scaling

### Mobile Access
1. Deploy API server to accessible IP/domain
2. Access HTML dashboard from mobile browser
3. Charts render and update automatically

**Example - Deploy to Network:**
```bash
# Get machine IP
ipconfig getifaddr en0  # macOS
hostname -I             # Linux

# Access from mobile
http://192.168.1.100:5001/dashboard_interactive.html
```

## 🔍 Integration Examples

### Export Data for Analysis

```python
from api_client import MonitoringAPIClient
import pandas as pd

client = MonitoringAPIClient("http://localhost:5001")
client.login("admin", "admin123")

# Get CPU timeline
# Note: This would need to be added to api_client.py
# For now, use requests directly
response = client.session.get(
    f"{client.api_url}/api/charts/cpu-timeline?hours=24",
    headers={"Authorization": f"Bearer {client.token}"}
)

data = response.json()
df = pd.DataFrame(data['data']['timeline'])
df.to_csv('cpu_metrics.csv')
```

### Embed in External Dashboard

```html
<!-- Embed in Grafana, Kibana, etc. -->
<iframe 
  src="http://your-server:5001/dashboard_interactive.html"
  width="100%"
  height="600"
></iframe>
```

### Generate Reports

```python
# Use metrics data to generate reports
summary = metrics_collector.get_summary_stats(hours=24)

print(f"CPU Average: {summary['cpu_avg']:.1f}%")
print(f"CPU Peak: {summary['cpu_max']:.1f}%")
print(f"Memory Average: {summary['memory_avg_percent']:.1f}%")
```

## 🐛 Troubleshooting

### No Data in Charts

**Problem:** Charts show empty or "no data"
**Solutions:**
1. Ensure API is collecting metrics: Check `metrics/metrics_history.jsonl` exists
2. Wait 5-10 minutes for initial data collection
3. Verify time range - may have insufficient historical data
4. Check API server logs for errors

### Connection Errors

**Problem:** "Cannot connect to API server"
**Solutions:**
1. Verify API server is running: `python api_server.py`
2. Check API URL in dashboard configuration
3. Verify port is accessible (default 5001)
4. Check firewall settings

### Authentication Errors

**Problem:** "Authentication expired" or "Invalid token"
**Solutions:**
1. Log out and log in again
2. Verify credentials: admin / admin123
3. Check token hasn't expired (24 hour default)
4. Clear browser cache/localStorage

### Slow Dashboards

**Problem:** Dashboard loads slowly or charts lag
**Solutions:**
1. Reduce time range (1 hour instead of 24 hours)
2. Reduce chart update frequency
3. Check system CPU/memory availability
4. Monitor API server performance

### Charts Not Updating

**Problem:** Charts show old data, not refreshing
**Solutions:**
1. Click "Refresh Now" button
2. Check auto-refresh rate setting
3. Verify API connectivity
4. Check browser console for JavaScript errors

## 📚 Related Documentation

- [REST API Guide](REST_API_GUIDE.md) - API endpoints reference
- [Process Control Guide](PROCESS_CONTROL_GUIDE.md) - Process management
- [Admin Panel Guide](ADMIN_PANEL_GUIDE.md) - Web admin interface
- [Windows Service Features](WINDOWS_SERVICE_FEATURES.md) - Service management

## 🎯 Best Practices

1. **Regular Data Review**
   - Review top processes weekly
   - Monitor CPU/memory trends
   - Identify performance issues early

2. **Alert Configuration**
   - Set thresholds for critical metrics
   - Configure alerts in admin panel
   - Monitor alert logs regularly

3. **Data Management**
   - Metrics retained for 7 days by default
   - Archive older data for long-term analysis
   - Use summaries for trend analysis

4. **Performance**
   - Limit time range to 24 hours for detailed analysis
   - Use summary endpoint for long-term trends
   - Monitor API server resources

5. **Security**
   - Protect dashboard with authentication
   - Use HTTPS in production
   - Restrict API access to trusted networks

## Summary

The visualization layer provides:
- ✅ **Real-time monitoring** with interactive charts
- ✅ **Multiple dashboard options** for different use cases
- ✅ **Historical data tracking** with 7-day retention
- ✅ **REST API** for programmatic access
- ✅ **Process-level analysis** for deep insights
- ✅ **Responsive design** for mobile access
- ✅ **Easy customization** for specific needs

Charts and visualizations make a huge impact on system monitoring presentation and enable quick identification of performance issues!
