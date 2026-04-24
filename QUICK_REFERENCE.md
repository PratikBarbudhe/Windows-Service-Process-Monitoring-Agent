# Quick Reference Guide

## Service Management Commands

```powershell
# Installation
python service_manager_cli.py install --auto-start     # Install with auto-start
python setup_service.py                                  # Interactive setup wizard

# Control
python service_manager_cli.py start                     # Start service
python service_manager_cli.py stop                      # Stop service
python service_manager_cli.py restart                   # Restart service
python service_manager_cli.py status                    # Show status

# Configuration
python service_manager_cli.py set-auto-start            # Enable auto-start
python service_manager_cli.py set-manual                # Set manual startup

# Removal
python service_manager_cli.py stop
python service_manager_cli.py remove
```

## Service Status Output

```
[*] Windows Service Process Monitoring Agent
    Status: Running              # Stopped | Starting | Running | Pausing | Paused | Stopping
    Startup: Automatic           # Automatic | Manual | Disabled
    Delayed Auto-start: Enabled  # [optional]
```

## Email Configuration (PowerShell Admin)

### Gmail
```powershell
[Environment]::SetEnvironmentVariable("WSPMA_EMAIL_ENABLED", "true", "Machine")
[Environment]::SetEnvironmentVariable("WSPMA_EMAIL_SENDER", "your-email@gmail.com", "Machine")
[Environment]::SetEnvironmentVariable("WSPMA_EMAIL_PASSWORD", "xxxx xxxx xxxx xxxx", "Machine")
[Environment]::SetEnvironmentVariable("WSPMA_EMAIL_RECIPIENTS", "admin@company.com", "Machine")
[Environment]::SetEnvironmentVariable("WSPMA_SMTP_SERVER", "smtp.gmail.com", "Machine")
[Environment]::SetEnvironmentVariable("WSPMA_SMTP_PORT", "587", "Machine")
```

### Office 365
```powershell
[Environment]::SetEnvironmentVariable("WSPMA_EMAIL_SENDER", "user@company.onmicrosoft.com", "Machine")
[Environment]::SetEnvironmentVariable("WSPMA_SMTP_SERVER", "smtp.office365.com", "Machine")
```

## Notification Settings (PowerShell Admin)

```powershell
# Enable/disable
[Environment]::SetEnvironmentVariable("WSPMA_NOTIFICATIONS_ENABLED", "true", "Machine")
[Environment]::SetEnvironmentVariable("WSPMA_EMAIL_ENABLED", "true", "Machine")

# Severity thresholds (CRITICAL, HIGH, MEDIUM, LOW, INFO)
[Environment]::SetEnvironmentVariable("WSPMA_NOTIFICATION_SEVERITY", "HIGH", "Machine")
[Environment]::SetEnvironmentVariable("WSPMA_EMAIL_SEVERITY", "HIGH", "Machine")

# Alert types
[Environment]::SetEnvironmentVariable("WSPMA_ALERT_SUSPICIOUS_PROCESS", "true", "Machine")
[Environment]::SetEnvironmentVariable("WSPMA_ALERT_SYSTEM_THRESHOLD", "true", "Machine")
[Environment]::SetEnvironmentVariable("WSPMA_ALERT_INJECTION", "true", "Machine")
[Environment]::SetEnvironmentVariable("WSPMA_ALERT_UNUSUAL_SERVICE", "true", "Machine")
```

## Batch Alerts & Rate Limiting

```powershell
# Email batching (send alerts as daily summary instead of individual)
[Environment]::SetEnvironmentVariable("WSPMA_EMAIL_BATCH", "true", "Machine")
[Environment]::SetEnvironmentVariable("WSPMA_EMAIL_BATCH_INTERVAL", "300", "Machine")

# Rate limiting (prevent alert storms)
[Environment]::SetEnvironmentVariable("WSPMA_RATE_LIMIT", "true", "Machine")
[Environment]::SetEnvironmentVariable("WSPMA_RATE_LIMIT_SECONDS", "60", "Machine")
```

## System Thresholds

```powershell
# Alert when resources exceed thresholds
[Environment]::SetEnvironmentVariable("WSPMA_CPU_THRESHOLD", "80.0", "Machine")
[Environment]::SetEnvironmentVariable("WSPMA_MEMORY_THRESHOLD", "85.0", "Machine")
[Environment]::SetEnvironmentVariable("WSPMA_DISK_THRESHOLD", "90.0", "Machine")
```

## Service Operation

```powershell
# Scan interval (seconds between monitoring scans)
[Environment]::SetEnvironmentVariable("MONITOR_SCAN_INTERVAL", "60", "Machine")

# Retry configuration
[Environment]::SetEnvironmentVariable("MONITOR_MAX_RETRIES", "3", "Machine")
[Environment]::SetEnvironmentVariable("MONITOR_RETRY_DELAY", "30", "Machine")
```

## Process Control Commands

### Kill Process

```powershell
# Graceful termination (10-second timeout)
python process_control_cli.py kill 1234 --reason "Malware detected"

# Force kill immediately
python process_control_cli.py kill 1234 --force --reason "Ransomware"
```

### Whitelist (Trusted Processes)

```powershell
# Add to whitelist
python process_control_cli.py whitelist "explorer.exe" --reason "Windows system process"

# List all whitelisted
python process_control_cli.py list-whitelist

# Remove from whitelist
python process_control_cli.py remove-whitelist "explorer.exe"
```

### Blacklist (Malicious Processes)

```powershell
# Add to blacklist (manual review before kill)
python process_control_cli.py blacklist "mimikatz.exe" --reason "Credential theft tool"

# Add with auto-kill (auto-terminate if detected)
python process_control_cli.py blacklist "ransomware.exe" --auto-block --reason "Ransomware"

# List all blacklisted
python process_control_cli.py list-blacklist

# Remove from blacklist
python process_control_cli.py remove-blacklist "mimikatz.exe"
```

### History & Status

```powershell
# View kill history
python process_control_cli.py history --limit 20

# Check if process is whitelisted/blacklisted
python process_control_cli.py check "notepad.exe"

# View statistics
python process_control_cli.py stats
```

## Process Control Configuration

```powershell
# Enable process control
[Environment]::SetEnvironmentVariable("WSPMA_PROCESS_CONTROL_ENABLED", "true", "Machine")

# Auto-kill blacklisted processes
[Environment]::SetEnvironmentVariable("WSPMA_AUTO_KILL_BLACKLISTED", "true", "Machine")

# Block process execution
[Environment]::SetEnvironmentVariable("WSPMA_AUTO_BLOCK_SUSPICIOUS", "true", "Machine")

# Blocking method (defender or applocker)
[Environment]::SetEnvironmentVariable("WSPMA_BLOCK_METHOD", "defender", "Machine")

# Kill on critical alert (use with caution!)
[Environment]::SetEnvironmentVariable("WSPMA_KILL_ON_CRITICAL", "false", "Machine")

# Require confirmation for auto-actions
[Environment]::SetEnvironmentVariable("WSPMA_REQUIRE_CONFIRMATION", "true", "Machine")
```

## View Logs

```powershell
# Real-time log monitoring
Get-Content logs/service_monitor.log -Tail 50 -Wait

# Search for alerts
Select-String "ALERT|ERROR" logs/service_monitor.log | Select-Object -Last 20

# Search for notifications
Select-String "notification|Email|Desktop" logs/service_monitor.log
```

## Verify Environment Variables

```powershell
# List all WSPMA variables
Get-ChildItem Env: | Where-Object { $_.Name -like "WSPMA_*" }

# Get specific variable
$env:WSPMA_EMAIL_ENABLED
[Environment]::GetEnvironmentVariable("WSPMA_EMAIL_ENABLED", "Machine")
```

## Features at a Glance

| Feature | Status | Command |
|---------|--------|---------|
| Auto-start on boot | ✅ | `set-auto-start` |
| Background operation | ✅ | (automatic) |
| Desktop notifications | ✅ | `WSPMA_NOTIFICATIONS_ENABLED` |
| Email alerts | ✅ | `WSPMA_EMAIL_ENABLED` |
| Batched emails | ✅ | `WSPMA_EMAIL_BATCH` |
| Rate limiting | ✅ | `WSPMA_RATE_LIMIT` |
| Service restart | ✅ | `restart` |
| Comprehensive logging | ✅ | `logs/service_monitor.log` |
| Health monitoring | ✅ | (automatic) |
| Alert thresholds | ✅ | Config-based |

## Common Tasks

### Setup Complete System
```powershell
# 1. Run setup wizard (easiest)
python setup_service.py

# 2. Manual setup
python service_manager_cli.py install --auto-start

# 3. Verify running
python service_manager_cli.py status
```

### Test Email Configuration
```powershell
# Set email config, then trigger manual scan
python monitor_agent.py --simulate

# Check logs for email send results
Select-String "Email alert sent" logs/service_monitor.log
```

### Monitor Service in Real-Time
```powershell
# Keep watching the logs
Get-Content logs/service_monitor.log -Tail 100 -Wait

# Or use Windows Event Viewer
# Event Viewer > Windows Logs > System
# Filter by "WindowsServiceProcessMonitor"
```

### Troubleshoot Issues
```powershell
# Check service status
python service_manager_cli.py status

# View recent errors in logs
Select-String "ERROR|CRITICAL|WARNING" logs/service_monitor.log | Select-Object -Last 30

# Check environment variables
Get-ChildItem Env: | Where-Object { $_.Name -like "WSPMA_*" } | Format-Table

# Restart service
python service_manager_cli.py restart
```

## Alert Severity Levels

```
CRITICAL  - Highest priority, immediate action required
HIGH      - Important, should be reviewed soon
MEDIUM    - Moderate priority, review when available
LOW       - Low priority, informational
INFO      - General informational messages
```

## Email Provider Settings

| Provider | Server | Port | TLS |
|----------|--------|------|-----|
| Gmail | smtp.gmail.com | 587 | Yes |
| Office 365 | smtp.office365.com | 587 | Yes |
| Outlook | smtp-mail.outlook.com | 587 | Yes |
| Custom | [your.server] | [port] | [yes/no] |

## Tips & Best Practices

1. **Gmail Setup**: Use App Passwords, not regular password
2. **Batch Emails**: Enable for reduced email volume
3. **Rate Limiting**: Enable to prevent alert fatigue
4. **Severity Filter**: Set thresholds to reduce noise
5. **Monitor Logs**: Regularly check `logs/service_monitor.log`
6. **Test First**: Run `python monitor_agent.py --simulate` before deployment
7. **Documentation**: See `SERVICE_INSTALLATION_GUIDE.md` for detailed setup

## Support

- Installation issues: See [SERVICE_INSTALLATION_GUIDE.md](SERVICE_INSTALLATION_GUIDE.md)
- Feature details: See [WINDOWS_SERVICE_FEATURES.md](WINDOWS_SERVICE_FEATURES.md)
- Source code: Check individual modules (notification_handler.py, windows_service.py, etc.)
