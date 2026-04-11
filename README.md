# Windows Service & Process Monitoring Agent

A comprehensive defensive security tool for detecting malicious, unauthorized, or suspicious process behavior on Windows systems.

## Overview

This monitoring agent analyzes Windows services and processes to identify anomalies including:
- Suspicious parent-child process relationships
- Unauthorized or blacklisted processes
- Malicious service configurations
- Process injection indicators
- Persistence mechanisms

## Features

### Process Monitoring
- ✅ Real-time process enumeration
- ✅ Parent-child relationship analysis
- ✅ Process tree visualization
- ✅ Suspicious behavior detection
- ✅ Process injection indicator detection
- ✅ Blacklist/whitelist-based filtering

### Service Auditing
- ✅ Windows service enumeration
- ✅ Startup service analysis
- ✅ Suspicious service path detection
- ✅ Service baseline comparison
- ✅ New service detection

### Alert System
- ✅ Multi-level severity alerts (Critical, High, Medium, Low, Info)
- ✅ Color-coded console output
- ✅ JSON alert logging
- ✅ Detailed alert descriptions

### Reporting
- ✅ Comprehensive text reports
- ✅ Executive summaries
- ✅ Timestamped logs
- ✅ Actionable recommendations

## Installation

### Prerequisites
- Windows operating system
- Python 3.7 or higher
- Administrator privileges (recommended for full functionality)

### Setup

1. **Clone or download the project**

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

The required packages are:
- `psutil` - Process and system utilities
- `pywin32` - Windows API access
- `wmi` - Windows Management Interface
- `colorama` - Colored terminal output

## Usage

### Basic Scan
Run a single monitoring scan:
```bash
python monitor_agent.py
```

### Continuous Monitoring
Monitor continuously with custom interval:
```bash
# Monitor every 60 seconds (default)
python monitor_agent.py --continuous

# Monitor every 5 minutes
python monitor_agent.py --continuous --interval 300
```

### Baseline Management
Create a baseline snapshot of current services:
```bash
python monitor_agent.py --baseline
```

Compare current state with baseline:
```bash
python monitor_agent.py --compare logs/service_baseline_20260410_120000.json
```

### Command-Line Options

| Option | Description |
|--------|-------------|
| `--continuous` | Run continuous monitoring |
| `--interval N` | Set monitoring interval in seconds (default: 60) |
| `--baseline` | Create baseline snapshot of services |
| `--compare FILE` | Compare current state with baseline file |

## Project Structure

```
.
├── monitor_agent.py          # Main entry point
├── process_analyzer.py       # Process enumeration and analysis
├── service_auditor.py        # Service auditing module
├── alert_manager.py          # Alert generation and management
├── report_generator.py       # Report generation
├── config.py                 # Configuration and detection rules
├── requirements.txt          # Python dependencies
├── README.md                 # This file
├── reports/                  # Generated reports directory
└── logs/                     # Alert logs and baselines
```

## Detection Capabilities

### Suspicious Process Relationships
Detects anomalous parent-child relationships such as:
- Microsoft Office spawning PowerShell/CMD
- Explorer.exe spawning scripting engines
- Legitimate processes spawning unexpected children

### Unauthorized Processes
Identifies:
- Known malicious executables (mimikatz, psexec, etc.)
- Processes running from suspicious locations (Temp, Public, etc.)
- Processes with missing executable paths (potential hollowing)

### Service Anomalies
Detects:
- Services running from suspicious locations
- Unknown auto-start services
- Newly added services
- Service configuration changes

## Output

### Console Output
- Color-coded alerts by severity
- Real-time monitoring progress
- Alert summaries

### Report Files
Reports are saved in the `reports/` directory:
- `monitoring_report_YYYYMMDD_HHMMSS.txt` - Comprehensive text report

### Alert Logs
JSON alert logs are saved in the `logs/` directory:
- `alerts_YYYYMMDD_HHMMSS.json` - Machine-readable alert data

## Configuration

Edit `config.py` to customize:

### Whitelists
Add legitimate processes to `PROCESS_WHITELIST`

### Blacklists
Add known malicious processes to `PROCESS_BLACKLIST`

### Suspicious Paths
Add monitored locations to `SUSPICIOUS_PATHS`

### Detection Rules
Customize `SUSPICIOUS_RELATIONSHIPS` to define parent-child rules

## Example Output

```
================================================================================
[HIGH] Suspicious Parent-Child Relationship
Time: 2026-04-10 14:32:15
Description: winword.exe spawned powershell.exe - potential malicious activity
Parent Name: winword.exe
Parent Pid: 4532
Child Name: powershell.exe
Child Pid: 7891
Child Path: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
================================================================================
```

## Security Considerations

⚠️ **Important Notes:**
- This tool is for **defensive security** and **authorized use only**
- Requires administrator privileges for full functionality
- May generate false positives - verify all alerts
- Not a replacement for professional EDR/antivirus solutions

## Use Cases

- ✅ Security monitoring and threat detection
- ✅ Incident response and forensics
- ✅ System baseline establishment
- ✅ Malware behavior analysis
- ✅ Security awareness and training
- ✅ CTF and security research

## Troubleshooting

### Access Denied Errors
Run PowerShell/CMD as Administrator

### Missing Dependencies
```bash
pip install -r requirements.txt --upgrade
```

### WMI Errors
Ensure Windows Management Instrumentation service is running

## Limitations

- Windows-only (requires win32 APIs)
- May miss kernel-mode rootkits
- Relies on signature-based and behavior-based detection
- False positives require manual verification

## Future Enhancements

- [ ] Network connection monitoring
- [ ] File system monitoring
- [ ] Registry monitoring
- [ ] Machine learning-based anomaly detection
- [ ] Web dashboard interface
- [ ] SIEM integration
- [ ] Email/webhook alerting

## License

Educational and defensive security use only.

## Author

Created for Windows security monitoring and defensive analysis.

## Disclaimer

This tool is provided for educational and defensive security purposes. Always ensure you have proper authorization before running security tools on any system.
