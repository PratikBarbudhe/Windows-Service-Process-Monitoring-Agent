# Admin Panel Documentation

## Overview

The Web-Based Admin Panel provides a complete management interface for the Windows Service Process Monitoring Agent, accessible via a web browser. It enables security teams to:

- **Authenticate** with a secure login system
- **Monitor** system status and real-time alerts
- **View logs** with filtering and search capabilities
- **Configure** system thresholds and settings
- **Manage** whitelist/blacklist processes
- **Track** process termination history for auditing

## 🚀 Getting Started

### Installation

1. **Install Flask dependency**:
```bash
pip install Flask>=2.3.0 Werkzeug>=2.3.0
```

Or install all dependencies:
```bash
pip install -r requirements.txt
```

### Starting the Admin Panel

```bash
# Run the admin panel
python admin_panel.py

# Then open browser at: http://localhost:5000
```

### Default Credentials

- **Username**: `admin`
- **Password**: `admin123`

⚠️ **IMPORTANT**: Change these credentials immediately in production!

## 📋 Features

### 1. Authentication & Login

Secure session-based authentication with:
- Username/password login
- Session management
- Automatic logout
- Activity logging

**Change Default Credentials**:

Edit `admin_panel.py`:
```python
from werkzeug.security import generate_password_hash

ADMIN_USERS = {
    "your_username": generate_password_hash("your_secure_password")
}
```

Restart the admin panel for changes to take effect.

### 2. Dashboard

Real-time overview of system status:

- **Process Control Statistics**
  - Whitelisted processes count
  - Blacklisted processes count
  - Auto-block enabled count
  - Total process kills
  
- **Service Status**
  - Service running/stopped
  - Installation status
  
- **System Configuration**
  - Process control enabled/disabled
  - Email alerts enabled/disabled
  
- **Recent Alerts**
  - Last 10 alerts from log files
  - Color-coded by severity
  - Quick drill-down links

### 3. Alert Log Viewer

Browse and search historical alerts:

**Features**:
- Select alert log file
- Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)
- Filter by alert type
- Search across alert content
- Pagination (50 alerts per page)
- Timestamp, process, and description display

**Use Cases**:
```
- Review incidents from specific date
- Search for specific process alerts
- Filter high-severity incidents
- Export data for reporting
```

### 4. Process Management

Manage whitelisted and blacklisted processes:

#### Whitelist Management
Add trusted processes to prevent false positives:

```
1. Enter process name (e.g., "explorer.exe")
2. Click "Add" button
3. Process added immediately
4. Auto-persisted to config/whitelist.json
```

#### Blacklist Management
Mark malicious processes for monitoring and control:

```
1. Enter process name
2. Check "AUTO-KILL" checkbox to auto-terminate if detected
3. Click "Add" button
4. Process blacklisted with configuration
```

**Workflow Example**:
```
Threat Intelligence Alert: "mimikatz.exe" credential theft tool
→ Add to blacklist via admin panel
→ Enable auto-kill checkbox
→ Process automatically terminated on next scan
→ Action logged to kill history
```

### 5. Configuration Interface

Manage system-wide settings:

#### System Thresholds
```
CPU Threshold:       80.0%    (alert when exceeded)
Memory Threshold:    85.0%    (alert when exceeded)
Disk Threshold:      90.0%    (alert when exceeded)
```

#### Notifications
- [x] Email Alerts - Send alerts via SMTP
- [ ] Desktop Notifications - Windows Toast popups
- Rate Limiting - Prevent alert storms

#### Process Control
- [x] Enable Process Control - Master enable/disable
- [x] Auto-kill Blacklisted - Auto-terminate on detection
- [ ] Auto-block Suspicious - Block execution
- [ ] Kill on Critical Alert - Dangerous, requires caution

#### Changes Applied
- Settings saved to environment variables
- Applied on next service restart
- Persistent across reboots

### 6. Kill History & Audit Trail

Complete audit log of all process terminations:

**Displays**:
- Timestamp of termination
- Process name and PID
- Kill method (graceful vs force)
- Success/failure status
- Reason for termination
- Full command path

**Statistics**:
- Total kills: 127
- Successful: 125
- Failed: 2

**Use Cases**:
- Compliance audit trail
- Incident forensics
- Performance analysis
- Security review

## 🔐 Security Considerations

### Authentication

**Best Practices**:
1. Change default credentials immediately
2. Use strong passwords (16+ characters)
3. Enable HTTPS in production
4. Set `app.secret_key` to a secure random value

**Production Setup**:
```python
# Set environment variable for secret key
import os
app.secret_key = os.environ.get("ADMIN_SECRET_KEY", "generate-random-key")
```

Generate secure secret key:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### Network Security

**For Production**:

1. **HTTPS Only** - Use reverse proxy (nginx/Apache) with SSL/TLS
2. **IP Restriction** - Limit access to trusted networks
3. **Firewall** - Only allow port 5000 from admin networks
4. **VPN** - Access through VPN tunnel

**Example Nginx Configuration**:
```nginx
server {
    listen 443 ssl http2;
    server_name admin.example.com;
    
    ssl_certificate /etc/ssl/certs/admin.crt;
    ssl_certificate_key /etc/ssl/private/admin.key;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
    }
}
```

### Data Protection

- Whitelist/blacklist stored in JSON files
- Kill history persisted locally
- Configuration in environment variables
- All modifications logged with username
- Session tokens in memory only

## 📊 Configuration Management

### Environment Variables

All settings can be controlled via environment variables:

```powershell
# System Thresholds
[Environment]::SetEnvironmentVariable("WSPMA_CPU_THRESHOLD", "85.0", "Machine")
[Environment]::SetEnvironmentVariable("WSPMA_MEMORY_THRESHOLD", "90.0", "Machine")
[Environment]::SetEnvironmentVariable("WSPMA_DISK_THRESHOLD", "95.0", "Machine")

# Notifications
[Environment]::SetEnvironmentVariable("WSPMA_EMAIL_ENABLED", "true", "Machine")

# Process Control
[Environment]::SetEnvironmentVariable("WSPMA_PROCESS_CONTROL_ENABLED", "true", "Machine")
[Environment]::SetEnvironmentVariable("WSPMA_AUTO_KILL_BLACKLISTED", "true", "Machine")

# Admin Panel
[Environment]::SetEnvironmentVariable("ADMIN_SECRET_KEY", "your-secure-key", "Machine")
[Environment]::SetEnvironmentVariable("WSPMA_LOG_DIR", "C:\logs", "Machine")
```

### Persistent Configuration

Configuration changes via admin panel are persisted through:

1. **Environment Variables** - Set at Machine level
2. **JSON Files** - Whitelist/blacklist in config/
3. **Service Restart** - Required to load new settings

## 🎯 Workflow Examples

### Example 1: Respond to Malware Alert

```
1. Dashboard shows new CRITICAL alert: "Ransomware signature detected"
2. Click alert to view details in Logs
3. Go to Processes tab
4. Add "ransomware.exe" to blacklist with auto-kill
5. Go to History tab to confirm kill
6. Export kill record for incident report
```

### Example 2: Configure Thresholds

```
1. Navigate to Configuration
2. Adjust CPU threshold from 80% to 70%
3. Adjust Memory threshold from 85% to 75%
4. Click "Save Thresholds"
5. Restart service to apply changes
6. New thresholds take effect
```

### Example 3: Whitelist Legitimate Process

```
1. Review false positive in Alert Logs
2. Identify legitimate process causing alert
3. Go to Processes tab
4. Whitelist the process with reason
5. Process added to allow list
6. Future scans skip this process
```

### Example 4: Audit Compliance Report

```
1. Go to History tab
2. View "Kill Statistics"
3. Click "Export" button
4. Save CSV to file
5. Include in compliance report
6. Demonstrate security controls in effect
```

## 🔧 Advanced Configuration

### Running Behind Reverse Proxy

```python
# In admin_panel.py, enable proxy headers
from werkzeug.middleware.proxy_fix import ProxyFix

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
```

### Customizing Admin Users

Add multiple admin accounts:

```python
from werkzeug.security import generate_password_hash

ADMIN_USERS = {
    "admin": generate_password_hash("admin123"),
    "security": generate_password_hash("secure_pass"),
    "analyst": generate_password_hash("analyst_pass")
}
```

### Logging

View admin panel logs:

```bash
# Check Python logging output
# Logs include:
# - Login/logout events
# - Configuration changes
# - Whitelist/blacklist modifications
# - Process kills
```

### Database Integration (Future)

For enterprise deployments, consider:
- PostgreSQL/MySQL for log persistence
- Elasticsearch for log searching
- LDAP/AD integration for authentication
- Multi-tenant support

## 🐛 Troubleshooting

### Admin Panel Won't Start

```bash
# Check if port 5000 is in use
netstat -ano | findstr :5000

# Use different port
# Edit admin_panel.py, change:
# app.run(port=8000)
```

### Login Not Working

```bash
# Verify credentials in ADMIN_USERS
# Default: admin / admin123

# Reset credentials:
# 1. Edit admin_panel.py
# 2. Update ADMIN_USERS dictionary
# 3. Restart admin panel
```

### Changes Not Persisting

```bash
# Whitelist/blacklist changes should be immediate
# Configuration changes require service restart:
python service_manager_cli.py restart

# Verify environment variables set:
[Environment]::GetEnvironmentVariable("WSPMA_CPU_THRESHOLD", "Machine")
```

### Performance Issues

```bash
# Admin panel runs on single thread
# For large deployments with many alerts:

# 1. Add gunicorn for production
pip install gunicorn

# 2. Run with multiple workers
gunicorn -w 4 -b 0.0.0.0:5000 admin_panel:app

# 3. Add caching layer for log files
# (Future enhancement)
```

## 📚 API Reference

All UI operations are backed by REST APIs:

### Authentication
```
POST /login
GET /logout
```

### Configuration
```
GET  /config
POST /api/config
```

### Process Management
```
POST   /api/whitelist
DELETE /api/whitelist/<name>
POST   /api/blacklist
DELETE /api/blacklist/<name>
```

### Logs & History
```
GET /logs
GET /history
```

## 🎓 Security Team Guide

### For SOC Analysts

**Daily Workflow**:
1. Check Dashboard for overnight alerts
2. Review critical/high severity in Logs
3. Add suspicious processes to blacklist
4. Monitor kill history for effectiveness
5. Document incidents

### For Security Engineers

**Weekly Tasks**:
1. Review whitelist for false positives
2. Audit blacklist effectiveness
3. Analyze kill history trends
4. Tune thresholds based on baseline
5. Update threat intelligence

### For Administrators

**Monthly Tasks**:
1. Review all log files
2. Update credentials
3. Audit access logs
4. Backup configuration
5. Test disaster recovery

## 📞 Support & Integration

### Command-line Tools

Complement the admin panel with CLI tools:

```bash
# Process control CLI
python process_control_cli.py list-whitelist
python process_control_cli.py whitelist "process.exe"

# Service management
python service_manager_cli.py status

# Monitor agent
python monitor_agent.py --continuous
```

### Integration Points

- Streamlit Dashboard: `python dashboard_streamlit.py`
- Windows Service: Auto-runs scans
- Email Notifications: Sent on alerts
- Alert Logs: JSON format for integration

## 🚀 Production Deployment

### Deployment Checklist

- [ ] Change default credentials
- [ ] Generate secure session key
- [ ] Configure HTTPS/reverse proxy
- [ ] Set up IP restrictions
- [ ] Enable logging
- [ ] Configure backup strategy
- [ ] Test disaster recovery
- [ ] Document access procedures
- [ ] Set up alerting for admin panel issues
- [ ] Schedule security reviews

### Monitoring the Admin Panel

```powershell
# Monitor admin panel health
Invoke-WebRequest http://localhost:5000/login

# Check service status
Get-Service "Windows Service Process Monitoring Agent"

# Review logs
Get-Content logs\*.json | ConvertFrom-Json | Where-Object {$_.timestamp -gt (Get-Date).AddHours(-1)}
```

## Summary

The Admin Panel provides a complete, production-ready management interface for enterprise security operations with:

✅ Secure authentication  
✅ Real-time dashboard  
✅ Log viewer with filtering  
✅ Configuration management  
✅ Whitelist/blacklist control  
✅ Audit trail and history  
✅ RESTful API backend  
✅ Responsive web interface  
✅ Complete documentation  

Perfect for security teams to manage threat detection and response from a unified web-based interface.
