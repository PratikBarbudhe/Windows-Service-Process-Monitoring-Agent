# Windows Service Features & System-Level Enhancements

## Overview

The Windows Service Process Monitoring Agent now includes comprehensive system-level enhancements to make it a proper Windows Service with auto-start capabilities, background operation, and full service control.

## ✅ System-Level Features Implemented

### 1. Proper Windows Service Implementation

The agent runs as a native Windows Service with:

- **Service Framework**: Uses Windows Service Control Manager (SCM) for lifecycle management
- **Service Identity**: Runs under specified account (SYSTEM or custom account)
- **Service Logging**: Integrated with Windows Event Viewer
- **Service Recovery**: Automatic restart on crash with exponential backoff
- **Process Isolation**: Runs independently with proper error handling

### 2. Auto-Start on Boot

Service can be configured to automatically start when the system boots:

```powershell
# Install with auto-start
python service_manager_cli.py install --auto-start
```

Features:
- **Startup Type**: Set to "Automatic" in registry
- **Delayed Auto-Start**: Configurable 30-60 second delay for system stability
- **Boot Sequence**: Service starts after critical system services
- **Recovery**: Automatic restart if service fails

### 3. Background Silent Operation

Service runs silently in the background with:

- **No Console Window**: Service runs without visible console
- **No User Interaction**: Fully automated operation
- **File-Based Logging**: All output to `logs/service_monitor.log`
- **Event Logging**: Windows Event Viewer integration
- **Resource Efficiency**: Optimized memory and CPU usage

### 4. Complete Service Control

Easy management via `service_manager_cli.py`:

```powershell
# Installation & Setup
python service_manager_cli.py install              # Install manually
python service_manager_cli.py install --auto-start # Install with auto-start

# Service Control
python service_manager_cli.py start                # Start service
python service_manager_cli.py stop                 # Stop service
python service_manager_cli.py restart              # Restart service
python service_manager_cli.py status               # Check status

# Configuration
python service_manager_cli.py set-auto-start       # Enable auto-start
python service_manager_cli.py set-manual           # Set to manual start
python service_manager_cli.py remove               # Uninstall service
```

## 📋 Service Architecture

```
┌─────────────────────────────────────────────┐
│  Windows Service Control Manager (SCM)      │
└────────────────────┬────────────────────────┘
                     │
        ┌────────────┴────────────┐
        │                         │
   ┌────▼──────────────┐   ┌─────▼──────────────┐
   │ Service Instance  │   │ Registry Settings  │
   │ (ServiceFramework)│   │ (Auto-start, etc)  │
   └────┬──────────────┘   └────────────────────┘
        │
   ┌────▼──────────────────────────────┐
   │ Monitoring Thread (Background)    │
   │  - Process Analysis               │
   │  - Service Auditing               │
   │  - Alert Generation               │
   └────┬───────────────────────────────┘
        │
   ┌────▼──────────────────────────────┐
   │ Notification Handler              │
   │  - Desktop Toast Notifications    │
   │  - Email Alerts (Batched)         │
   │  - Rate Limiting                  │
   └────────────────────────────────────┘
```

## 🚀 Quick Start Guide

### Installation (requires Administrator)

```powershell
# Option 1: Interactive Setup Wizard
python setup_service.py

# Option 2: Manual Installation
python service_manager_cli.py install --auto-start
```

### Configuration

Set environment variables as `Machine` (system-wide):

```powershell
# Notifications
[Environment]::SetEnvironmentVariable("WSPMA_NOTIFICATIONS_ENABLED", "true", "Machine")
[Environment]::SetEnvironmentVariable("WSPMA_EMAIL_ENABLED", "true", "Machine")

# Email Configuration
[Environment]::SetEnvironmentVariable("WSPMA_EMAIL_SENDER", "admin@company.com", "Machine")
[Environment]::SetEnvironmentVariable("WSPMA_EMAIL_PASSWORD", "app-password", "Machine")
[Environment]::SetEnvironmentVariable("WSPMA_EMAIL_RECIPIENTS", "security@company.com", "Machine")

# Service Operation
[Environment]::SetEnvironmentVariable("MONITOR_SCAN_INTERVAL", "60", "Machine")
```

### Operation

```powershell
# Start monitoring
python service_manager_cli.py start

# Check status
python service_manager_cli.py status

# View logs
Get-Content logs/service_monitor.log -Tail 50 -Wait
```

## 📊 Service Features in Detail

### 1. Registry-Based Configuration

Service settings stored in Windows Registry:

```
HKEY_LOCAL_MACHINE
├─ SYSTEM
   └─ CurrentControlSet
      └─ Services
         └─ WindowsServiceProcessMonitor
            ├─ Start (2=Automatic, 3=Manual, 4=Disabled)
            ├─ DelayedAutoStart (1=Enabled, 0=Disabled)
            ├─ Description
            └─ ImagePath
```

### 2. Health Monitoring & Recovery

- **Thread Health Checks**: Monitors monitoring thread status
- **Memory Monitoring**: Alerts on high memory usage
- **Automatic Restart**: Restarts on fatal errors
- **Exponential Backoff**: Gradually increases retry delays
- **Max Retry Limit**: Stops retrying after threshold

### 3. Logging Architecture

```
logs/
├─ service_monitor.log         # Main service log (rotating)
├─ alerts_YYYYMMDD_HHMMSS.json # Alert snapshots
└─ [rotated backups]           # service_monitor.log.1, .2, etc.
```

Features:
- **Rotation**: Max 10MB per file, keep 5 backups
- **Comprehensive**: All scans, alerts, errors logged
- **Timestamps**: Full datetime for all events
- **Levels**: DEBUG, INFO, WARNING, ERROR

### 4. Notification Integration

#### Desktop Notifications
- Windows 10 Toast notifications
- Configurable duration (default 10 seconds)
- Alert severity display
- Message truncation for long descriptions

#### Email Notifications
- SMTP support (Gmail, Office 365, etc.)
- HTML and plain-text formats
- Batched sending (optional)
- Alert summary emails
- Rate limiting per alert type

### 5. Error Handling & Resilience

- **Exception Handling**: Comprehensive try-catch blocks
- **Graceful Degradation**: Service continues if notification fails
- **Thread Safety**: Proper synchronization for multi-threaded operation
- **Resource Cleanup**: Proper file and resource closure
- **Timeout Handling**: Prevents infinite waits

## 🔧 Environment Variables

### Notification Settings

```
WSPMA_NOTIFICATIONS_ENABLED        # bool: Enable desktop notifications (default: true)
WSPMA_EMAIL_ENABLED                # bool: Enable email alerts (default: false)
WSPMA_NOTIFICATION_SEVERITY        # str: Min severity for notifications (HIGH)
WSPMA_EMAIL_SEVERITY               # str: Min severity for emails (HIGH)
```

### Email Configuration

```
WSPMA_EMAIL_SENDER                 # str: Sender email address
WSPMA_EMAIL_PASSWORD               # str: SMTP password or app password
WSPMA_EMAIL_RECIPIENTS             # str: Comma-separated recipient list
WSPMA_SMTP_SERVER                  # str: SMTP server (default: smtp.gmail.com)
WSPMA_SMTP_PORT                    # int: SMTP port (default: 587)
WSPMA_EMAIL_USE_TLS                # bool: Use TLS (default: true)
```

### Alert Triggers

```
WSPMA_ALERT_SUSPICIOUS_PROCESS     # bool: Notify on suspicious processes
WSPMA_ALERT_SYSTEM_THRESHOLD       # bool: Notify on system threshold exceeded
WSPMA_ALERT_INJECTION              # bool: Notify on injection detected
WSPMA_ALERT_UNUSUAL_SERVICE        # bool: Notify on unusual services
```

### Rate Limiting

```
WSPMA_RATE_LIMIT                   # bool: Enable rate limiting (default: true)
WSPMA_RATE_LIMIT_SECONDS           # int: Min seconds between alerts (default: 60)
WSPMA_EMAIL_BATCH                  # bool: Batch email alerts (default: true)
WSPMA_EMAIL_BATCH_INTERVAL         # int: Batch flush interval in seconds (300)
```

### Service Operation

```
MONITOR_SCAN_INTERVAL              # int: Seconds between scans (default: 60)
MONITOR_MAX_RETRIES                # int: Max consecutive failures (default: 3)
MONITOR_RETRY_DELAY                # int: Delay between retries (default: 30)
```

### System Thresholds

```
WSPMA_CPU_THRESHOLD                # float: CPU alert threshold % (default: 80.0)
WSPMA_MEMORY_THRESHOLD             # float: Memory alert threshold % (default: 85.0)
WSPMA_DISK_THRESHOLD               # float: Disk alert threshold % (default: 90.0)
```

## 📝 Service Status Output

```powershell
PS> python service_manager_cli.py status

[*] Windows Service Process Monitoring Agent
    Status: Running
    Startup: Automatic
    Delayed Auto-start: Enabled
```

## 🔐 Security Considerations

1. **Credential Storage**: Passwords stored in environment variables (use App Passwords)
2. **File Permissions**: Service logs restricted to SYSTEM user
3. **Registry Access**: Registry modifications require admin
4. **Service Account**: Runs under SYSTEM for full system access
5. **Event Logging**: All service events logged to Windows Event Log

## 📦 Files Added/Modified

### New Files
- `service_manager_cli.py` - Service management CLI
- `setup_service.py` - Interactive setup wizard
- `notification_handler.py` - Email & desktop notification handler
- `SERVICE_INSTALLATION_GUIDE.md` - Detailed setup instructions

### Modified Files
- `windows_service.py` - Enhanced with notification integration
- `config.py` - Added notification configuration options
- `requirements.txt` - Added `win10toast` dependency

## 🧪 Testing the Service

### Test Installation
```powershell
python service_manager_cli.py install --auto-start
python service_manager_cli.py status
```

### Test Notifications
```powershell
# Enable email (set environment variables first)
# Run a manual scan to trigger alerts
python monitor_agent.py --simulate

# Check notifications sent in logs
Get-Content logs/service_monitor.log | Select-String "notification"
```

### Test Recovery
```powershell
# Service should auto-restart if stopped externally
python service_manager_cli.py stop
Start-Sleep 5
python service_manager_cli.py status
# Should show "Running" if auto-recovery working
```

## 🐛 Troubleshooting

### Service Won't Start
- Check logs: `logs/service_monitor.log`
- Verify admin privileges
- Reinstall with: `python service_manager_cli.py remove && python service_manager_cli.py install`

### No Notifications
- Check environment variables are set
- Verify notification severity threshold
- Check logs for notification errors
- Ensure win10toast is installed

### Email Not Sending
- Verify SMTP credentials
- Check SMTP server/port
- For Gmail, use App Password (not regular password)
- Check logs for SMTP errors

### High Memory Usage
- Check monitoring thread health
- Reduce scan interval
- Increase retry delays

## 📚 Additional Resources

- [SERVICE_INSTALLATION_GUIDE.md](SERVICE_INSTALLATION_GUIDE.md) - Detailed setup guide
- [config.py](config.py) - Configuration reference
- [windows_service.py](windows_service.py) - Service implementation details
- [notification_handler.py](notification_handler.py) - Notification system details

## 🎯 Summary

The Windows Service implementation provides:

✅ Automatic startup on boot  
✅ Silent background operation  
✅ Complete service control (start/stop/restart/status)  
✅ Email and desktop notifications  
✅ Comprehensive logging  
✅ Automatic error recovery  
✅ Registry-based configuration  
✅ Event logging integration  
✅ Easy installation & setup  
✅ Production-ready resilience  

This makes the agent suitable for enterprise deployment and continuous monitoring in production environments.
