# Windows Service Process Monitoring Agent

A comprehensive Windows service for monitoring processes and services with security-focused heuristics.

## Features

- **Windows Service Integration**: Proper service lifecycle management (start/stop/restart)
- **Comprehensive Logging**: Structured logging with rotation and multiple levels
- **Error Handling**: Robust error recovery and retry mechanisms
- **Process Monitoring**: Real-time process enumeration and anomaly detection
- **Service Auditing**: Windows service configuration analysis
- **Alert Management**: Deduplication and severity-based alerting
- **Reporting**: Automated report generation and export

## Installation

### Prerequisites

- Windows 10/11 with Administrator privileges
- Python 3.9+
- Required Python packages (install via pip)

```bash
pip install -r requirements.txt
```

### Service Installation

1. **Install the service** (run as Administrator):
```bash
python service_manager.py install --start-type auto
```

2. **Start the service**:
```bash
python service_manager.py start
```

3. **Check service status**:
```bash
python service_manager.py status
```

### Service Management

```bash
# View detailed service information
python service_manager.py info

# Restart the service
python service_manager.py restart

# Stop the service
python service_manager.py stop

# Uninstall the service
python service_manager.py stop
python service_manager.py uninstall
```

### Service Logs

Monitor service activity in real-time:
```bash
python service_manager.py logs
```

Service logs are stored in `logs/service_monitor.log` with automatic rotation.

## Configuration

### Environment Variables

Configure service behavior via environment variables:

```bash
# Scan interval in seconds (default: 60)
set MONITOR_SCAN_INTERVAL=120

# Maximum consecutive failures before stopping (default: 3)
set MONITOR_MAX_RETRIES=5

# Delay between retries in seconds (default: 30)
set MONITOR_RETRY_DELAY=60
```

### Service Configuration

The service automatically:
- Runs with Local System privileges
- Starts automatically on system boot
- Restarts automatically on failure
- Logs to `logs/service_monitor.log`
- Exports reports to `reports/` directory
- Saves alerts to `logs/` directory

## Monitoring Features

### Process Analysis
- Process enumeration via psutil
- Parent-child relationship analysis
- Command-line pattern detection
- Path-based security checks
- Process injection detection
- Orphan process identification

### Service Auditing
- Service enumeration (WMI/SCM)
- Configuration analysis
- Auto-start service detection
- Suspicious service identification
- Baseline comparison

### Alert System
- Severity-based classification (Critical/High/Medium/Low/Info)
- Deduplication across scans
- Structured JSON export
- CSV export for analysis
- Console and file logging

## Usage Examples

### CLI Mode (Development/Testing)

```bash
# Single scan
python monitor_agent.py

# Continuous monitoring
python monitor_agent.py --continuous --interval 120

# Create service baseline
python monitor_agent.py --baseline

# Compare with baseline
python monitor_agent.py --compare logs/service_baseline_20240101_120000.json
```

### Service Mode (Production)

Once installed as a service, monitoring runs automatically in the background.

## Troubleshooting

### Common Issues

1. **Service won't start**
   - Ensure running as Administrator
   - Check Python path and dependencies
   - Review service logs: `python service_manager.py logs`

2. **Permission errors**
   - Service runs as Local System by default
   - Some process information requires elevated privileges

3. **High CPU usage**
   - Adjust scan interval: `set MONITOR_SCAN_INTERVAL=300`
   - Check for monitoring loops or infinite retries

4. **Service crashes**
   - Check logs for error details
   - Ensure all dependencies are installed
   - Verify Windows service permissions

### Log Analysis

```bash
# View recent errors
python service_manager.py logs | Select-String "ERROR"

# Check service health
python service_manager.py info
```

## Architecture

### Components

- **`windows_service.py`**: Windows service implementation
- **`service_manager.py`**: Service management utilities
- **`monitor_agent.py`**: Core monitoring logic
- **`process_analyzer.py`**: Process analysis engine
- **`service_auditor.py`**: Service auditing engine
- **`alert_manager.py`**: Alert management system
- **`report_generator.py`**: Report generation

### Service Lifecycle

1. **Start**: Initialize monitoring components and logging
2. **Run**: Execute monitoring scans at configured intervals
3. **Stop**: Gracefully shutdown monitoring thread
4. **Restart**: Clean restart with proper cleanup

### Error Handling

- **Retry Logic**: Automatic retry on transient failures
- **Exponential Backoff**: Increasing delays for consecutive failures
- **Graceful Degradation**: Continue monitoring other components if one fails
- **Comprehensive Logging**: All errors logged with context

## Security Considerations

- Runs with Local System privileges (required for full monitoring)
- Logs sensitive information (review log permissions)
- Network access may be required for some WMI operations
- Consider log encryption for production deployments

## Development

### Testing the Service

```bash
# Test service components without installing
python -c "from windows_service import WindowsServiceProcessMonitor; print('Service class loads OK')"

# Test monitoring logic
python monitor_agent.py --simulate

# Validate service manager
python service_manager.py status
```

### Building Executables

```bash
# Create standalone executable
python build_exe.py

# The executable will be in build/ directory
```

## License

See ATTRIBUTIONS.md for third-party component licenses.