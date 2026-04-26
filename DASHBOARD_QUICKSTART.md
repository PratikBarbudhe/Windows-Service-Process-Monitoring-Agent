# Interactive Dashboard Quick Start

Get your monitoring dashboard up and running in 60 seconds!

## What You Get

A professional, responsive web dashboard with:
- 📊 **CPU usage timeline** - See performance trends over time
- 💾 **Memory usage chart** - Track memory consumption
- 🔝 **Top processes** - Identify resource-hungry applications
- ⚡ **Real-time metrics** - System overview cards
- 🔄 **Auto-refresh** - Automatic updates (30s-5m)
- 📱 **Mobile responsive** - Works on phones and tablets

## Prerequisites

✅ **Python 3.7+**  
✅ **API server running** (`python api_server.py` or via Windows Service)  
✅ **Web browser** (Chrome, Firefox, Safari, Edge)

## Step 1: Start the API Server

```bash
# Option A: Direct Python
python api_server.py

# Option B: Via Windows Service (if installed)
net start ProcessMonitoringAgent
```

You should see:
```
 * Running on http://127.0.0.1:5001
```

## Step 2: Open the Dashboard

### Option A: From File System
1. Navigate to project folder
2. Right-click `dashboard_interactive.html`
3. Select "Open with" → Your browser
4. Or: Double-click the file

### Option B: Via HTTP (For Network Access)
```bash
# Python 3.7+
python -m http.server 8000 --directory .

# Then open: http://localhost:8000/dashboard_interactive.html
# Or from another machine: http://your-ip:8000/dashboard_interactive.html
```

### Option C: Direct Path
```
file:///C:/path/to/dashboard_interactive.html
```

## Step 3: Configure Connection

When dashboard opens first time:

1. **API Server URL** - Should show `http://localhost:5001` ✓
2. **Username** - Enter: `admin`
3. **Password** - Enter: `admin123`
4. Click **Login**

Dashboard will authenticate and load data.

> ⚠️ Change default credentials in production!

## Step 4: View Your Data

Charts will populate with:
- ✅ **Metric cards** - Current CPU, memory, processes
- ✅ **CPU timeline** - Last 24 hours of CPU usage
- ✅ **Memory timeline** - Memory trends
- ✅ **Top 10 processes** - By CPU and memory usage

## Customizing the Dashboard

### Change Time Range
Dropdown menu: "Last 1 Hour" / "Last 6 Hours" / "Last 24 Hours"

### Auto-Refresh Rate
Dropdown menu: 30 seconds to 5 minutes
- Faster = more responsive but higher CPU usage
- Slower = lower resource usage

### Manual Refresh
Click **🔄 Refresh Now** button anytime

### API Configuration
Right-click → "Inspect" → Console or click logout to change settings

## Chart Types Explained

### CPU Usage Timeline (Line Chart)
Shows system CPU percentage over time
- **X-axis:** Time
- **Y-axis:** CPU % (0-100)
- **Use:** Identify peak times, performance issues

### Memory Usage Timeline (Area Chart)
Shows system memory percentage over time
- **X-axis:** Time  
- **Y-axis:** Memory % (0-100)
- **Use:** Spot memory leaks, usage patterns

### Top Processes by CPU (Bar Chart)
Top 10 processes consuming most CPU
- **Horizontal bars:** Processes ranked by average CPU
- **Color:** Purple (#667eea)
- **Use:** Find resource hogs

### Top Processes by Memory (Bar Chart)
Top 10 processes using most memory
- **Horizontal bars:** Processes ranked by memory MB
- **Color:** Dark purple (#764ba2)
- **Use:** Identify memory consumers

## Troubleshooting

### "Cannot connect to API server"
```
✓ Is API server running? (python api_server.py)
✓ Check port 5001 is available
✓ Firewall blocking port?
✓ URL correct in config?
```

**Solution:**
```bash
# Test API connectivity
curl http://localhost:5001/api/health

# Or in Python
python -c "import requests; requests.get('http://localhost:5001/api/health')"
```

### "Login failed"
```
✓ Correct credentials? (admin / admin123)
✓ Check API server logs
✓ Are credentials changed in config.py?
```

**Solution:**
```bash
# Check config
grep -n "API_USER\|API_PASS" config.py
```

### "No data in charts"
```
✓ Wait 5-10 minutes for initial data collection
✓ Check metrics file exists: metrics/metrics_history.jsonl
✓ Verify time range selected
```

**Solution:**
```bash
# Check if metrics collected
ls -la metrics/
cat metrics/metrics_history.jsonl | head -5
```

### Charts update slowly
```
✓ Check auto-refresh rate (set to 1 min first)
✓ Verify API performance
✓ Monitor system resources
✓ Try shorter time range (1 hour instead of 24)
```

## Advanced Usage

### Embed in Web Page
```html
<iframe 
  src="file:///path/to/dashboard_interactive.html"
  width="1200" 
  height="800"
  frameborder="0">
</iframe>
```

### Deploy to Web Server
1. Copy `dashboard_interactive.html` to web root
2. Configure API URL to your server hostname
3. Access: `http://your-hostname/dashboard_interactive.html`

### Network Monitoring
```bash
# Access from another machine on network
http://192.168.1.100:5001/  # API server
python -m http.server 8000   # Serve dashboard

# Then visit from another PC
http://192.168.1.100:8000/dashboard_interactive.html
```

### Data Export
Right-click chart → "Save Image As..." to save snapshots
Or use browser DevTools to extract underlying data:
```javascript
// In browser console
console.log(state.charts.cpu.data)  // CPU chart data
```

## Features Reference

| Feature | Menu | Function |
|---------|------|----------|
| Time Range | Dropdown | Select 1/6/24 hours |
| Auto-Refresh | Dropdown | Set 30s-5m interval |
| Manual Refresh | Button | Update now |
| Login | On load | Enter credentials |
| Metrics | Cards | Quick stats view |
| Charts | Main area | Detailed visualization |

## Performance Tips

1. **Mobile/Slow Connection:**
   - Use 30-minute refresh rate
   - Select 1-hour time range
   - Close other browser tabs

2. **High-Resolution Screens:**
   - Charts will auto-scale
   - Performance is GPU-assisted

3. **Server Performance:**
   - Monitor API server CPU usage
   - Reduce refresh rate if server load high
   - Archive old metrics monthly

## Browser Compatibility

| Browser | Version | Status |
|---------|---------|--------|
| Chrome | 60+ | ✅ Perfect |
| Firefox | 55+ | ✅ Perfect |
| Safari | 12+ | ✅ Good |
| Edge | 79+ | ✅ Perfect |

## Next Steps

### 1. Generate Report
```bash
python report_generator.py --hours 24 --format pdf
```

### 2. Set Up Alerts
Configure in admin panel: `python admin_panel.py`

### 3. Automate Collection
Edit `monitor_agent.py` to integrate metrics collection

### 4. Custom Charts
Modify dashboard HTML to add more visualizations

### 5. Mobile App
Use API endpoints to build iOS/Android monitoring app

## Keyboard Shortcuts

- **F5** - Refresh page
- **F12** - Open DevTools
- **Ctrl+Shift+K** - Console
- **Esc** - Close modals

## Support

**API Issues:**
- Check `logs/` directory for API errors
- Verify `config.py` settings
- Test endpoints with curl/Postman

**Dashboard Issues:**
- Check browser console (F12)
- Verify JavaScript enabled
- Clear cache: Ctrl+Shift+Delete

**Metrics Issues:**
- Verify `metrics/metrics_history.jsonl` exists
- Check disk space available
- Ensure Python has file permissions

## Summary

Your interactive dashboard is now ready to:
- ✅ Monitor CPU and memory in real-time
- ✅ Identify resource-consuming processes
- ✅ Track performance trends
- ✅ Display data beautifully
- ✅ Work on any device

**Start monitoring now!** Open `dashboard_interactive.html` in your browser.

---

For detailed information: See [VISUALIZATION_GUIDE.md](VISUALIZATION_GUIDE.md)
