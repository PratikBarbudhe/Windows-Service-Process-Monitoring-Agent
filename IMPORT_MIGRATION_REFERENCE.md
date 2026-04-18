# Quick Reference: Import Migration Cheat Sheet

## File Location Mapping

| Old Path | New Path |
|----------|----------|
| `./alert_manager.py` | `src/wspma/core/alert_manager.py` |
| `./process_analyzer.py` | `src/wspma/core/process_analyzer.py` |
| `./service_auditor.py` | `src/wspma/core/service_auditor.py` |
| `./monitor_agent.py` | `src/wspma/cli/agent.py` |
| `./config.py` | `src/wspma/config/settings.py` |
| `./path_utils.py` | `src/wspma/utils/path_utils.py` |
| `./report_generator.py` | `src/wspma/reporting/report_generator.py` |

## Import Statement Changes

### AlertManager
```python
# OLD
from alert_manager import AlertManager

# NEW
from wspma.core.alert_manager import AlertManager
```

### ProcessAnalyzer
```python
# OLD
from process_analyzer import ProcessAnalyzer

# NEW
from wspma.core.process_analyzer import ProcessAnalyzer
```

### ServiceAuditor
```python
# OLD
from service_auditor import ServiceAuditor

# NEW
from wspma.core.service_auditor import ServiceAuditor
```

### Configuration
```python
# OLD
import config
config.SEVERITY_CRITICAL

# NEW
from wspma.config import settings
settings.SEVERITY_CRITICAL
```

### Utilities
```python
# OLD
from path_utils import ensure_alert_path_field

# NEW
from wspma.utils.path_utils import ensure_alert_path_field
```

### Reporting
```python
# OLD
from report_generator import ReportGenerator

# NEW
from wspma.reporting.report_generator import ReportGenerator
```

## Top-level Imports (From src/wspma/__init__.py)

For convenience, users can import directly from uspma:

```python
# This works after proper __init__.py setup
from wspma import AlertManager, ProcessAnalyzer, ServiceAuditor, ReportGenerator

# Shorthand for specific modules
from wspma.core import AlertManager, ProcessAnalyzer, ServiceAuditor
from wspma.utils import ensure_alert_path_field
from wspma.config import settings
```

## Running the Agent

### Before Migration
```bash
python monitor_agent.py --help
python monitor_agent.py --continuous
```

### After Migration
```bash
# New: Package-based execution
python -m wspma --help
python -m wspma --continuous

# Old still works if installed
wspma --help
```

## Directory Structure Tree

```
project/
├── src/wspma/
│   ├── __init__.py                  # Package initialization
│   ├── __main__.py                  # Entry point for python -m wspma
│   ├── core/
│   │   ├── __init__.py
│   │   ├── alert_manager.py
│   │   ├── process_analyzer.py
│   │   └── service_auditor.py
│   ├── cli/
│   │   ├── __init__.py
│   │   └── agent.py
│   ├── config/
│   │   ├── __init__.py
│   │   └── settings.py
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── path_utils.py
│   │   └── demo_scenarios.py
│   ├── reporting/
│   │   ├── __init__.py
│   │   └── report_generator.py
│   ├── models/                      # (New: for dataclasses)
│   │   └── __init__.py
│   ├── detection/                   # (New: for extracted logic)
│   │   └── __init__.py
│   └── gui/
│       ├── __init__.py
│       ├── components.py
│       ├── main_window.py
│       └── ...
├── tests/
│   ├── __init__.py
│   ├── unit/
│   ├── integration/
│   └── fixtures/
├── config/
│   ├── detection_rules.yaml
│   ├── severity_mappings.json
│   └── exclusions.txt
├── docs/
├── output/
├── logs/
├── pyproject.toml
├── README.md
└── ...
```

## Setup Commands (Phase 1 - Directory Setup)

```bash
# Create package structure
mkdir -p src/wspma/{core,config,utils,reporting,detection,models,cli,gui,storage}

# Create test structure
mkdir -p tests/{unit,integration,fixtures}

# Create other directories
mkdir -p docs config scripts output logs

# Create __init__ files
touch src/wspma/__init__.py
touch src/wspma/core/__init__.py
touch src/wspma/config/__init__.py
touch src/wspma/utils/__init__.py
touch src/wspma/reporting/__init__.py
touch src/wspma/detection/__init__.py
touch src/wspma/models/__init__.py
touch src/wspma/cli/__init__.py
touch src/wspma/gui/__init__.py
```

## Verification Commands

```bash
# After migration, test imports
python -c "from wspma import AlertManager; print('✓ Import successful')"
python -c "from wspma.core import AlertManager, ProcessAnalyzer, ServiceAuditor; print('✓ All core imports OK')"

# Test CLI entry point
python -m wspma --help

# Run tests
pytest tests/ -v
```

## Troubleshooting

**Import Error: No module named 'wspma'**
```bash
# Install in development mode
pip install -e .
```

**ImportError in old files**
```bash
# If old root-level files still exist, rename them (.bak)
mv alert_manager.py alert_manager.py.bak
```

**Circular imports**
- Ensure __init__.py files are minimal
- Delay imports if necessary: `from wspma.core import AlertManager` inside functions

**Path resolution issues**
- Use relative imports within package: `from . import settings`
- Use absolute imports from outside: `from wspma.config import settings`
