# Process Control Features

## Overview

The Windows Service Process Monitoring Agent now includes comprehensive process control features that allow security teams to:

- **Kill suspicious processes** - Terminate detected malicious or suspicious processes
- **Block process execution** - Prevent processes from running via Windows Defender or AppLocker
- **Whitelist trusted processes** - Mark known-good processes to prevent false positives
- **Blacklist malicious processes** - Mark known-bad processes for blocking and automatic termination
- **Process kill history** - Track all process terminations for auditing and review

## ✅ Features Implemented

### 1. Kill Suspicious Process

Terminate processes with options for graceful or force termination:

```powershell
# Graceful termination (10-second timeout)
python process_control_cli.py kill 1234 --reason "Malware detected"

# Force termination
python process_control_cli.py kill 1234 --force --reason "Ransomware - immediate action required"
```

Features:
- **Graceful Termination**: Allows process to clean up (10-second timeout)
- **Force Termination**: Immediate kill without cleanup
- **Process Validation**: Confirms process exists before attempting kill
- **Error Handling**: Graceful failure if process already terminated
- **Audit Trail**: Records all kill attempts with timestamp and reason
- **Return Status**: Success/failure indication for automation

### 2. Block Process Execution

Prevent processes from running using system capabilities:

```powershell
# Block via Windows Defender (recommended)
python process_control_cli.py block "malware.exe" --method defender

# Block via AppLocker (requires AppLocker configured)
python process_control_cli.py block "malware.exe" --method applocker
```

Methods:
- **Windows Defender**: Uses exclusion/threat management
- **AppLocker**: Creates executable block rules (requires Windows Pro/Enterprise)
- **Configuration**: Via `WSPMA_BLOCK_METHOD` environment variable

Implementation:
- Registry-based configuration
- PowerShell integration for rule application
- Requires administrator privileges
- Can be automated for critical threats

### 3. Whitelist Trusted Processes

Mark processes as known-good to reduce false positives:

```powershell
# Whitelist a process
python process_control_cli.py whitelist "explorer.exe" --reason "Windows system process"

# With full path
python process_control_cli.py whitelist "notepad.exe" --path "C:\Windows\notepad.exe" --reason "User application"

# View whitelist
python process_control_cli.py list-whitelist

# Remove from whitelist
python process_control_cli.py remove-whitelist "explorer.exe"
```

Features:
- **By Name**: Whitelist by process executable name
- **By Path**: Whitelist by full executable path for specificity
- **Reason Tracking**: Document why process is whitelisted
- **Persistent Storage**: Whitelist saved to `config/whitelist.json`
- **Fast Lookup**: O(1) whitelist checking

### 4. Blacklist Malicious Processes

Mark processes as known-bad for automatic handling:

```powershell
# Blacklist a process (manual kill only)
python process_control_cli.py blacklist "mimikatz.exe" --reason "Credential theft tool"

# Blacklist with auto-kill (automatically terminate if detected)
python process_control_cli.py blacklist "ransomware.exe" --auto-block --reason "Ransomware variant"

# View blacklist
python process_control_cli.py list-blacklist

# Remove from blacklist
python process_control_cli.py remove-blacklist "mimikatz.exe"
```

Features:
- **By Name**: Blacklist by process executable name
- **By Path**: Blacklist by full executable path
- **Auto-block**: Enable automatic termination when detected
- **Reason Tracking**: Document threat classification
- **Persistent Storage**: Blacklist saved to `config/blacklist.json`
- **Service Integration**: Auto-kill triggered during monitoring scans

### 5. Process Kill History

Track all process terminations for audit and forensics:

```powershell
# View kill history
python process_control_cli.py history

# View last 20 kills
python process_control_cli.py history --limit 20

# View statistics
python process_control_cli.py stats
```

History Records:
- PID and process name
- Full executable path
- Termination timestamp
- Reason for termination
- Kill method (graceful vs force)
- Success/failure status
- Error messages if failed
- Persistent storage in `config/kill_history.json`

### 6. Process Status Checking

Check if a process is whitelisted or blacklisted:

```powershell
# Check process status
python process_control_cli.py check "explorer.exe"

# Output example:
# [*] Process Status: explorer.exe
# Whitelisted: Yes
# Blacklisted: No
```

## 📋 CLI Commands Reference

### Process Termination

```powershell
python process_control_cli.py kill <PID> [--reason "text"] [--force]
```

Parameters:
- `PID`: Process ID to terminate
- `--reason`: Reason for termination (logged)
- `--force`: Skip graceful termination, force kill immediately

### Whitelisting

```powershell
python process_control_cli.py whitelist <name> [--path "path"] [--reason "text"]
python process_control_cli.py remove-whitelist <name>
python process_control_cli.py list-whitelist
```

### Blacklisting

```powershell
python process_control_cli.py blacklist <name> [--path "path"] [--reason "text"] [--auto-block]
python process_control_cli.py remove-blacklist <name>
python process_control_cli.py list-blacklist
```

### History & Status

```powershell
python process_control_cli.py history [--limit N]
python process_control_cli.py check <name> [--path "path"]
python process_control_cli.py stats
```

## 🔧 Configuration

### Environment Variables

```powershell
# Enable process control
[Environment]::SetEnvironmentVariable("WSPMA_PROCESS_CONTROL_ENABLED", "true", "Machine")

# Auto-kill processes in blacklist when detected
[Environment]::SetEnvironmentVariable("WSPMA_AUTO_KILL_BLACKLISTED", "true", "Machine")

# Block execution of suspicious processes
[Environment]::SetEnvironmentVariable("WSPMA_AUTO_BLOCK_SUSPICIOUS", "true", "Machine")

# Blocking method (defender or applocker)
[Environment]::SetEnvironmentVariable("WSPMA_BLOCK_METHOD", "defender", "Machine")

# Kill on critical alert (dangerous - use with caution)
[Environment]::SetEnvironmentVariable("WSPMA_KILL_ON_CRITICAL", "false", "Machine")

# Require confirmation for automatic actions
[Environment]::SetEnvironmentVariable("WSPMA_REQUIRE_CONFIRMATION", "true", "Machine")
```

### File Locations

```
config/
├─ whitelist.json       # Whitelisted processes
├─ blacklist.json       # Blacklisted processes
└─ kill_history.json    # Process termination history
```

### Configuration Files Format

**whitelist.json**
```json
{
  "explorer.exe": {
    "name": "explorer.exe",
    "path": null,
    "hash_value": null,
    "reason": "Windows system process",
    "added_at": "2026-04-23T10:30:00",
    "added_by": "admin",
    "auto_block": false
  }
}
```

**blacklist.json**
```json
{
  "mimikatz.exe": {
    "name": "mimikatz.exe",
    "path": null,
    "hash_value": null,
    "reason": "Credential theft tool - APT activity",
    "added_at": "2026-04-23T10:35:00",
    "added_by": "socanalist",
    "auto_block": true
  }
}
```

## 🔐 Security Considerations

### Graceful vs Force Termination

**Graceful (Default)**
- Sends termination signal
- Allows process to clean up (10-second timeout)
- Safer for critical services
- May be ignored by malicious processes

**Force Kill**
- Immediate process termination
- No cleanup opportunity
- Use for unresponsive processes
- May cause data loss or system instability

### Whitelist Best Practices

1. **System Processes**: Explorer.exe, services.exe, svchost.exe
2. **Legitimate Applications**: Browsers, Office, development tools
3. **Regular Review**: Audit whitelist quarterly
4. **Be Specific**: Use full paths when possible
5. **Document Rationale**: Always provide reason for whitelisting

### Blacklist Best Practices

1. **Threat Intelligence**: Use known malware hashes/names
2. **Auto-block Carefully**: Only for high-confidence threats
3. **Test First**: Verify in isolated environment
4. **Monitor Impact**: Watch for legitimate process false positives
5. **Keep Updated**: Maintain current threat indicators

### Automatic Actions

⚠️ **WARNING**: Automatic process killing can impact system stability.

**Safe Configurations:**
- Auto-kill only CRITICAL severity + high confidence
- Require confirmation for all actions
- Disable auto-block on production until tested
- Monitor kill history for unexpected terminations

**Dangerous Configurations:**
- Auto-kill on all HIGH severity (too many false positives)
- `WSPMA_KILL_ON_CRITICAL=true` without confirmation
- Blacklist common processes

## 📊 Integration with Monitoring

### Automatic Response to Alerts

```python
# In monitor_agent.py
process_control = ProcessControlManager()

# For blacklisted process with auto-block
if alert.get("severity") == "CRITICAL":
    if process_control.is_blacklisted(process_name):
        if process_control.blacklist[name].auto_block:
            record = process_control.kill_process(
                pid,
                reason=f"Auto-killed: {alert['type']}"
            )
            # Send alert notification
```

### Alert Generation on Kill

Kill attempts generate alerts:
- Process name and PID
- Termination timestamp
- Success/failure status
- Kill method used
- Reason for termination

## 🧪 Testing & Validation

### Test Graceful Termination

```powershell
# Launch test process
Start-Process notepad

# Get PID
$pid = (Get-Process notepad).Id

# Gracefully terminate
python process_control_cli.py kill $pid --reason "Testing graceful termination"

# Verify process terminated
Get-Process notepad -ErrorAction SilentlyContinue  # Should be empty
```

### Test Whitelisting

```powershell
# Whitelist explorer.exe
python process_control_cli.py whitelist "explorer.exe" --reason "System process"

# Verify
python process_control_cli.py check "explorer.exe"
# Should show: Whitelisted: Yes
```

### Test Auto-block

```powershell
# Blacklist with auto-block
python process_control_cli.py blacklist "test_malware.exe" --auto-block

# Verify
python process_control_cli.py list-blacklist
# Should show: Auto-block: Yes

# Check during service scan - process will be auto-killed
python service_manager_cli.py restart
```

## 📈 Statistics & Monitoring

View process control statistics:

```powershell
python process_control_cli.py stats

# Output:
# Process Control Statistics
# Whitelisted Processes: 15
# Blacklisted Processes: 8
# Auto-block Enabled: 3
# Total Kills: 127
#   - Successful: 125
#   - Failed: 2
```

## 🎯 Use Cases

### 1. Rapid Response to Malware

```powershell
# Alert triggered for ransomware
# 1. Kill the malicious process
python process_control_cli.py kill 3456 --force --reason "Ransomware detected - immediate action"

# 2. Blacklist with auto-block
python process_control_cli.py blacklist "ransomware.exe" --auto-block --reason "Ransomware - CRI-2026-001"

# 3. Block execution system-wide
python process_control_cli.py block "ransomware.exe" --method defender
```

### 2. APT Campaign Response

```powershell
# Multiple malicious processes detected
# 1. Kill all instances
python process_control_cli.py kill 1111 --reason "APT-28 tool: mimikatz"
python process_control_cli.py kill 2222 --reason "APT-28 tool: psexec"
python process_control_cli.py kill 3333 --reason "APT-28 tool: bloodhound"

# 2. Blacklist all with auto-block
python process_control_cli.py blacklist "mimikatz.exe" --auto-block --reason "APT-28"
python process_control_cli.py blacklist "psexec.exe" --auto-block --reason "APT-28"
python process_control_cli.py blacklist "bloodhound.exe" --auto-block --reason "APT-28"

# 3. Enable auto-kill for critical phase
[Environment]::SetEnvironmentVariable("WSPMA_AUTO_KILL_BLACKLISTED", "true", "Machine")
```

### 3. Credential Dumping Prevention

```powershell
# Whitelist legitimate system tools
python process_control_cli.py whitelist "ntdsutil.exe" --reason "Legitimate AD backup tool"
python process_control_cli.py whitelist "vssadmin.exe" --reason "Legitimate volume shadow copy utility"

# Blacklist known credential theft tools
python process_control_cli.py blacklist "mimikatz.exe" --auto-block --reason "Credential theft"
python process_control_cli.py blacklist "procdump.exe" --auto-block --reason "Memory dumping"
python process_control_cli.py blacklist "ntdsdump.exe" --auto-block --reason "AD database dumping"
```

## 📝 Audit & Compliance

### Kill History for Auditing

All process terminations are logged:

```json
{
  "pid": 1234,
  "name": "malware.exe",
  "path": "C:\\Temp\\malware.exe",
  "timestamp": "2026-04-23T14:30:15.123456",
  "reason": "Critical alert: Ransomware signature match",
  "kill_method": "force",
  "success": true,
  "error_message": null
}
```

### Compliance Reporting

```powershell
# Generate kill history report
$history = python process_control_cli.py history | ConvertFrom-Json
$history | Export-Csv -Path "kill_history_$(Get-Date -f 'yyyyMMdd').csv"

# Monthly statistics
$stats = python process_control_cli.py stats | ConvertFrom-Json
"Month: $(Get-Date -f 'yyyy-MM'), Kills: $($stats.kill_history_count)" | Add-Content "monthly_report.txt"
```

## 🔍 Troubleshooting

### Process Won't Die

```powershell
# Try force kill
python process_control_cli.py kill 1234 --force

# Check for elevation
# Process control requires admin privileges
# Run as Administrator

# Verify PID exists
Get-Process -Id 1234 -ErrorAction SilentlyContinue
```

### Whitelist Not Working

1. Verify whitelisted process name matches exactly
2. Check case sensitivity (uses lowercase internally)
3. Verify `config/whitelist.json` file exists
4. Check file permissions on config directory

### Auto-block Not Triggering

1. Verify `WSPMA_AUTO_KILL_BLACKLISTED=true`
2. Check process is in blacklist with `--auto-block` flag
3. Run manual test: `python process_control_cli.py kill <PID>`
4. Check service logs for auto-kill attempts

## 📚 Related Documentation

- [SERVICE_INSTALLATION_GUIDE.md](SERVICE_INSTALLATION_GUIDE.md) - Service setup
- [WINDOWS_SERVICE_FEATURES.md](WINDOWS_SERVICE_FEATURES.md) - Service features
- [QUICK_REFERENCE.md](QUICK_REFERENCE.md) - Command reference
- [notification_handler.py](notification_handler.py) - Alert notifications

## Summary

Process control features provide:

✅ Kill suspicious processes (graceful & force)  
✅ Block process execution (Defender & AppLocker)  
✅ Whitelist trusted processes  
✅ Blacklist malicious processes  
✅ Automatic process termination on detection  
✅ Complete kill history audit trail  
✅ CLI management interface  
✅ Persistent configuration storage  
✅ Integration with alert system  
✅ Production-ready error handling  

These features enable rapid response to security threats while maintaining system stability through whitelisting and manual confirmation options.
