# Windows Service Installation & Management Guide

## Overview

The Windows Service Process Monitoring Agent can be installed as a Windows Service that:
- Automatically starts on system boot
- Runs silently in the background with proper logging
- Sends email and desktop notifications for security alerts
- Can be easily controlled via CLI commands

## Prerequisites

- Windows 7 or later
- Administrator privileges for service installation
- Python 3.8+ configured in PATH
- All dependencies installed: `pip install -r requirements.txt`

## Installation Steps

### 1. Install Service with Auto-Start

Run the following command in PowerShell or Command Prompt **as Administrator**:

```powershell
cd F:\Windows-Service-Process-Monitoring-Agent
python service_manager_cli.py install --auto-start
```

This will:
- Install the Windows Service
- Configure it to start automatically on boot
- Enable delayed auto-start (starts 30-60 seconds after boot for stability)

### 2. Configure Notifications (Optional)

Before starting the service, configure email and/or desktop notifications:

#### Email Configuration

Set environment variables:

```powershell
# PowerShell (as Administrator)
[Environment]::SetEnvironmentVariable("WSPMA_EMAIL_ENABLED", "true", "Machine")
[Environment]::SetEnvironmentVariable("WSPMA_EMAIL_SENDER", "your-email@gmail.com", "Machine")
[Environment]::SetEnvironmentVariable("WSPMA_EMAIL_PASSWORD", "your-app-password", "Machine")
[Environment]::SetEnvironmentVariable("WSPMA_EMAIL_RECIPIENTS", "admin@company.com,security@company.com", "Machine")
[Environment]::SetEnvironmentVariable("WSPMA_SMTP_SERVER", "smtp.gmail.com", "Machine")
[Environment]::SetEnvironmentVariable("WSPMA_SMTP_PORT", "587", "Machine")
```

#### Desktop Notifications

Desktop notifications are enabled by default (if `win10toast` is installed):

```powershell
[Environment]::SetEnvironmentVariable("WSPMA_NOTIFICATIONS_ENABLED", "true", "Machine")
```

#### Alert Thresholds

Configure which alert types trigger notifications:

```powershell
# Enable/disable notification types
[Environment]::SetEnvironmentVariable("WSPMA_ALERT_SUSPICIOUS_PROCESS", "true", "Machine")
[Environment]::SetEnvironmentVariable("WSPMA_ALERT_SYSTEM_THRESHOLD", "true", "Machine")
[Environment]::SetEnvironmentVariable("WSPMA_ALERT_INJECTION", "true", "Machine")
[Environment]::SetEnvironmentVariable("WSPMA_ALERT_UNUSUAL_SERVICE", "true", "Machine")

# Minimum severity to notify (CRITICAL, HIGH, MEDIUM, LOW, INFO)
[Environment]::SetEnvironmentVariable("WSPMA_NOTIFICATION_SEVERITY", "HIGH", "Machine")
[Environment]::SetEnvironmentVariable("WSPMA_EMAIL_SEVERITY", "HIGH", "Machine")
```

#### Rate Limiting & Batching

```powershell
# Rate limit: minimum seconds between same alert type
[Environment]::SetEnvironmentVariable("WSPMA_RATE_LIMIT_SECONDS", "60", "Machine")

# Email batching: batch alerts and send together
[Environment]::SetEnvironmentVariable("WSPMA_EMAIL_BATCH", "true", "Machine")
[Environment]::SetEnvironmentVariable("WSPMA_EMAIL_BATCH_INTERVAL", "300", "Machine")
```

#### System Thresholds

```powershell
# CPU usage threshold (percentage)
[Environment]::SetEnvironmentVariable("WSPMA_CPU_THRESHOLD", "80.0", "Machine")

# Memory usage threshold (percentage)
[Environment]::SetEnvironmentVariable("WSPMA_MEMORY_THRESHOLD", "85.0", "Machine")

# Disk usage threshold (percentage)
[Environment]::SetEnvironmentVariable("WSPMA_DISK_THRESHOLD", "90.0", "Machine")
```

#### Service Scan Interval

```powershell
# Seconds between monitoring scans (default: 60)
[Environment]::SetEnvironmentVariable("MONITOR_SCAN_INTERVAL", "60", "Machine")

# Max consecutive failures before logging error
[Environment]::SetEnvironmentVariable("MONITOR_MAX_RETRIES", "3", "Machine")

# Delay between retries (seconds)
[Environment]::SetEnvironmentVariable("MONITOR_RETRY_DELAY", "30", "Machine")
```

### 3. Start the Service

```powershell
python service_manager_cli.py start
```

## Service Management Commands

### Check Service Status

```powershell
python service_manager_cli.py status
```

Output example:
```
[*] Windows Service Process Monitoring Agent
    Status: Running
    Startup: Automatic
    Delayed Auto-start: Enabled
```

### Stop Service

```powershell
python service_manager_cli.py stop
```

### Restart Service

```powershell
python service_manager_cli.py restart
```

### Configure Auto-Start (after installation)

```powershell
python service_manager_cli.py set-auto-start
```

### Configure Manual Start (after installation)

```powershell
python service_manager_cli.py set-manual
```

### Remove Service

```powershell
python service_manager_cli.py stop
python service_manager_cli.py remove
```

## Service Logging

Service logs are written to: `logs/service_monitor.log`

The log file:
- Rotates when it reaches 10MB
- Keeps 5 backup files
- Includes all monitoring scans, alerts, and errors
- Includes notification delivery status

View logs:
```powershell
# Real-time monitoring
Get-Content logs/service_monitor.log -Tail 100 -Wait

# Search for errors
Select-String "ERROR|ALERT" logs/service_monitor.log | Select-Object -Last 50
```

## Notification Features

### Desktop Notifications

- Automatic Windows 10 Toast notifications for alerts
- Configurable severity threshold
- Alert type filtering
- Rate limiting to prevent notification storms

### Email Notifications

- SMTP support (Gmail, Office 365, etc.)
- HTML and plain-text email formats
- Batched alerts (optional) for daily summaries
- Alert severity and type filtering
- Rate limiting per alert type

#### Gmail Configuration Example

1. Enable 2-Step Verification in Google Account
2. Create App Password: https://myaccount.google.com/apppasswords
3. Use app password in `WSPMA_EMAIL_PASSWORD`

```powershell
[Environment]::SetEnvironmentVariable("WSPMA_EMAIL_SENDER", "your-email@gmail.com", "Machine")
[Environment]::SetEnvironmentVariable("WSPMA_EMAIL_PASSWORD", "xxxx xxxx xxxx xxxx", "Machine")
[Environment]::SetEnvironmentVariable("WSPMA_SMTP_SERVER", "smtp.gmail.com", "Machine")
```

## Service Recovery Options

The Windows service includes automatic recovery:

1. **Automatic Restart on Crash**
   - Service automatically restarts if it fails
   - Exponential backoff for retries
   - Max 5-minute delay between retries

2. **Health Monitoring**
   - Monitoring thread health checks
   - Memory usage monitoring
   - Automatic recovery from failures

### Manual Recovery

To manually restart if service gets stuck:

```powershell
# Stop and restart
python service_manager_cli.py restart
```

## Uninstallation

```powershell
# Stop the service
python service_manager_cli.py stop

# Remove from Windows
python service_manager_cli.py remove

# Verify removal
Get-Service WindowsServiceProcessMonitor -ErrorAction SilentlyContinue
```

## Troubleshooting

### Service Won't Start

1. Check administrator privileges are enabled
2. Review logs: `logs/service_monitor.log`
3. Verify all dependencies installed: `pip install -r requirements.txt`
4. Check Python path is correct

### No Notifications Being Sent

1. Check notification is enabled: `WSPMA_NOTIFICATIONS_ENABLED`
2. Verify severity threshold: `WSPMA_NOTIFICATION_SEVERITY`
3. Check alert type filters are enabled
4. Check service logs for notification errors

### Email Not Sending

1. Verify SMTP credentials are correct
2. Check sender/recipients configured
3. For Gmail, ensure App Password is used (not regular password)
4. Verify network connectivity
5. Check `logs/service_monitor.log` for SMTP errors

### High Memory Usage

1. Check log rotation is working
2. Adjust scan interval: `MONITOR_SCAN_INTERVAL`
3. Review process analyzer settings in `config.py`
4. Consider increasing service restart interval

## Advanced Configuration

### Custom Log Directory

```powershell
[Environment]::SetEnvironmentVariable("WSPMA_LOG_DIR", "C:\Logs\Monitoring", "Machine")
```

### Custom Output Directory

```powershell
[Environment]::SetEnvironmentVariable("WSPMA_OUTPUT_DIR", "C:\Reports", "Machine")
```

### Service Parameters

Edit environment variables to customize:

```powershell
[Environment]::SetEnvironmentVariable("WSPMA_NOTIFICATIONS_ENABLED", "true", "Machine")
[Environment]::SetEnvironmentVariable("WSPMA_EMAIL_ENABLED", "true", "Machine")
[Environment]::SetEnvironmentVariable("WSPMA_RATE_LIMIT", "true", "Machine")
```

## Security Best Practices

1. **Use App Passwords for Gmail** instead of real password
2. **Restrict File Permissions** on logs directory
3. **Monitor Service Logs** regularly
4. **Set Appropriate Severity Thresholds** to avoid alert fatigue
5. **Enable Rate Limiting** to prevent notification storms
6. **Batch Emails** for daily summaries instead of real-time
7. **Test Notifications** before production deployment

## Windows Service Events

Service events are logged to Windows Event Viewer:

```
Event Viewer > Windows Logs > System
```

Look for events from "Service Control Manager" with source `WindowsServiceProcessMonitor`

## Integration with Other Tools

The service creates outputs that can be integrated with:

- **SIEM Systems**: JSON alerts in `logs/alerts_*.json`
- **Email Systems**: Configured via SMTP settings
- **Monitoring Dashboards**: Via Streamlit dashboard
- **Reports**: Daily/weekly reports in `reports/` directory

## Support & Feedback

For issues or suggestions:
1. Check `logs/service_monitor.log`
2. Review configuration in `config.py`
3. Test with manual scan: `python monitor_agent.py`
4. Verify environment variables are set correctly
