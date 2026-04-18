# Recommended Folder Structure

## Proposed Organization

```
windows-service-monitoring-agent/
├── README.md                          # Project overview and setup
├── LICENSE                            # License file
├── .gitignore                         # Git ignore rules
├── pyproject.toml                     # Python package metadata
├── requirements.txt                   # Production dependencies
├── requirements-dev.txt               # Development dependencies
├── CONTRIBUTING.md                    # Contribution guidelines
├── CHANGELOG.md                       # Release notes and changes
│
├── src/                               # Main source code
│   └── wspma/                         # Package name (Windows Service Process Monitoring Agent)
│       ├── __init__.py
│       ├── __main__.py                # CLI entry point
│       │
│       ├── core/                      # Core monitoring logic
│       │   ├── __init__.py
│       │   ├── process_analyzer.py    # Process detection & heuristics
│       │   ├── service_auditor.py     # Service enumeration & auditing
│       │   └── alert_manager.py       # Alert aggregation & dedup
│       │
│       ├── detection/                 # Detection methods & rules
│       │   ├── __init__.py
│       │   ├── process_detectors.py   # Process-specific detections
│       │   ├── service_detectors.py   # Service-specific detections
│       │   └── heuristics.py          # Common detection rules
│       │
│       ├── models/                    # Data models & structures
│       │   ├── __init__.py
│       │   ├── alert.py               # Alert data model
│       │   ├── process.py             # Process information model
│       │   └── service.py             # Service information model
│       │
│       ├── reporting/                 # Report generation
│       │   ├── __init__.py
│       │   ├── report_generator.py    # Report creation
│       │   ├── exporters.py           # CSV, JSON export implementations
│       │   └── formatters.py          # Output formatting utilities
│       │
│       ├── config/                    # Configuration management
│       │   ├── __init__.py
│       │   ├── settings.py            # Configuration loading
│       │   ├── defaults.py            # Default settings
│       │   └── rules.py               # Detection rules configuration
│       │
│       ├── utils/                     # Shared utilities
│       │   ├── __init__.py
│       │   ├── path_utils.py          # Path manipulation
│       │   ├── logging.py             # Logging configuration
│       │   ├── winapi.py              # Windows API wrappers
│       │   └── validators.py          # Input validation
│       │
│       ├── cli/                       # Command-line interface
│       │   ├── __init__.py
│       │   ├── commands.py            # CLI commands implementation
│       │   └── formatter.py           # Console output formatting
│       │
│       ├── storage/                   # Data persistence
│       │   ├── __init__.py
│       │   ├── baseline.py            # Baseline management
│       │   └── serializers.py         # JSON/pickle serialization
│       │
│       └── gui/                       # GUI components (optional)
│           ├── __init__.py
│           ├── main_window.py
│           ├── components.py
│           └── styles.py
│
├── tests/                             # Test suite
│   ├── __init__.py
│   ├── conftest.py                    # Pytest configuration & fixtures
│   │
│   ├── unit/                          # Unit tests
│   │   ├── __init__.py
│   │   ├── test_process_analyzer.py
│   │   ├── test_service_auditor.py
│   │   ├── test_alert_manager.py
│   │   └── test_detectors.py
│   │
│   ├── integration/                   # Integration tests
│   │   ├── __init__.py
│   │   ├── test_end_to_end_scan.py
│   │   └── test_baseline_compare.py
│   │
│   └── fixtures/                      # Test data & fixtures
│       ├── __init__.py
│       ├── sample_processes.py
│       ├── sample_services.py
│       └── sample_alerts.json
│
├── docs/                              # Documentation
│   ├── README.md
│   ├── installation.md                # Installation guide
│   ├── usage.md                       # Usage guide
│   ├── configuration.md               # Configuration reference
│   ├── api.md                         # API reference
│   ├── architecture.md                # Architecture overview
│   ├── detection-rules.md             # Detection heuristics explanation
│   └── troubleshooting.md             # Troubleshooting guide
│
├── config/                            # Configuration files
│   ├── default_config.json            # Default settings
│   ├── detection_rules.yaml           # Detection rule definitions
│   ├── severity_mappings.json         # Severity level mappings
│   └── exclusions.txt                 # Whitelisted processes/services
│
├── scripts/                           # Utility scripts
│   ├── build_exe.py                   # PyInstaller build script
│   ├── setup_env.py                   # Environment setup
│   ├── run_tests.py                   # Test runner
│   └── generate_docs.py               # Documentation generator
│
├── output/                            # Generated outputs (gitignored)
│   ├── reports/                       # Generated reports
│   │   ├── monitoring_summary_*.txt
│   │   └── monitoring_detailed_*.txt
│   ├── json/                          # Structured output
│   │   └── scan_*.json
│   ├── csv/                           # Tabular exports
│   │   └── alerts_*.csv
│   └── baselines/                     # Service baselines for comparison
│       └── service_baseline_*.json
│
├── logs/                              # Application logs (gitignored)
│   ├── agent_*.log                    # Main application logs
│   ├── scan_*.log                     # Scan session logs
│   └── errors_*.log                   # Error logs
│
├── data/                              # Persistent data (gitignored)
│   ├── cache/                         # Process/service caches
│   ├── baselines/                     # Baseline snapshots
│   └── metrics/                       # Performance metrics
│
├── .github/                           # GitHub specific files
│   ├── workflows/                     # CI/CD workflows
│   │   ├── tests.yml
│   │   ├── build.yml
│   │   └── release.yml
│   └── ISSUE_TEMPLATE/
│       └── bug_report.md
│
├── docker/                            # Docker configuration (optional)
│   ├── Dockerfile
│   └── docker-compose.yml
│
├── build/                             # Build artifacts (gitignored)
│   └── dist/                          # Distribution packages
│
└── .env.example                       # Environment variables template

```

## Folder Descriptions

### **Core Folders**

| Folder | Purpose |
|--------|---------|
| `src/wspma/` | Main package source code with clear separation of concerns |
| `src/wspma/core/` | Core monitoring engines (process, service, alerts) |
| `src/wspma/detection/` | Pluggable detection methods and heuristics |
| `src/wspma/models/` | Dataclass models for type safety and clarity |
| `src/wspma/config/` | Configuration management and rule loading |
| `src/wspma/utils/` | Reusable utilities (logging, Windows APIs, validation) |
| `src/wspma/reporting/` | Report generation and export formats |
| `src/wspma/storage/` | Persistence layer (baselines, serialization) |

### **Testing & Quality**

| Folder | Purpose |
|--------|---------|
| `tests/unit/` | Unit tests for individual components |
| `tests/integration/` | End-to-end scenario tests |
| `tests/fixtures/` | Mock data and test fixtures |

### **Documentation & Configuration**

| Folder | Purpose |
|--------|---------|
| `docs/` | User and developer documentation |
| `config/` | Runtime configuration files (not code) |
| `scripts/` | Build, setup, and utility scripts |

### **Output & Runtime**

| Folder | Purpose |
|--------|---------|
| `output/` | Generated reports, scans, exports (gitignored) |
| `logs/` | Application runtime logs (gitignored) |
| `data/` | Persistent data directory (gitignored) |

## Migration Steps

```bash
# 1. Organize source code
mv alert_manager.py src/wspma/core/
mv process_analyzer.py src/wspma/core/
mv service_auditor.py src/wspma/core/
mv report_generator.py src/wspma/reporting/
mv config.py src/wspma/config/

# 2. Create empty __init__.py files
touch src/wspma/__init__.py
touch src/wspma/core/__init__.py
touch src/wspma/detection/__init__.py
# ... (for all package subdirectories)

# 3. Move GUI components
mv gui/ src/wspma/gui/

# 4. Move utility modules
mv path_utils.py src/wspma/utils/

# 5. Update imports in all files
# Change: import config → from wspma.config import settings
# Change: from alert_manager → from wspma.core.alert_manager
# ... (update all relative imports to absolute)

# 6. Create __main__.py for CLI entry
touch src/wspma/__main__.py
```

## Benefits of This Structure

✓ **Separation of Concerns** — Each module has a clear, single responsibility  
✓ **Scalability** — Easy to add new detection methods, output formats, or storage backends  
✓ **Testability** — Clean boundaries make unit and integration testing straightforward  
✓ **Maintainability** — New developers quickly understand the architecture  
✓ **Python Best Practices** — Follows PEP 420 (namespace packages) and standard layouts  
✓ **Modularity** — Detection logic, reporting, and configuration are independent  
✓ **Extensibility** — Plugin architecture supports custom detectors and exporters  

## Configuration as Code

Instead of hardcoded values scattered across modules, store configurations in `config/`:

```yaml
# config/detection_rules.yaml
process_detections:
  suspicious_relationships:
    - parent: "winword.exe"
      suspicious_children: ["powershell.exe", "cmd.exe"]
  
service_detections:
  suspicious_paths:
    - "\\temp\\"
    - "\\downloads\\"

severity_overrides:
  - process: "mimikatz.exe"
    severity: "CRITICAL"
```

This allows non-technical users to tune detection rules without modifying code.

## Package Distribution

With this structure, you can easily distribute as:
- **PyPI Package**: `pip install windows-service-monitoring-agent`
- **Executable**: `pyinstaller --onefile src/wspma/__main__.py`
- **Docker Container**: Package to container for centralized scanning

