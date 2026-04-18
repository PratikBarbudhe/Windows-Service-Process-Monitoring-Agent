# Implementation Guide: Folder Structure Migration

This guide walks through restructuring your project for better organization and maintainability.

## Current State vs. Proposed Structure

### Current Structure (Root Level)
```
project/
├── alert_manager.py
├── process_analyzer.py
├── service_auditor.py
├── monitor_agent.py
├── config.py
├── path_utils.py
├── report_generator.py
├── gui/
└── reports/, logs/
```

### Proposed Structure (Package-Based)
```
project/
├── src/wspma/
│   ├── core/              (process_analyzer, service_auditor, alert_manager)
│   ├── config/            (config, defaults)
│   ├── utils/             (path_utils, logging)
│   ├── reporting/         (report_generator)
│   ├── detection/         (new: extracted detection logic)
│   ├── models/            (new: data models)
│   └── cli/               (monitor_agent refactored)
├── tests/
├── docs/
├── output/
└── logs/
```

## Step-by-Step Migration Plan

### Phase 1: Directory Setup (No Code Changes)

```bash
# Create main package structure
mkdir -p src/wspma/{core,config,utils,reporting,detection,models,cli,gui,storage}
mkdir -p tests/{unit,integration,fixtures}
mkdir -p docs
mkdir -p config
mkdir -p scripts
mkdir -p .github/workflows

# Create __init__ files
for dir in src/wspma src/wspma/{core,config,utils,reporting,detection,models,cli,gui,storage}
do
  touch "$dir/__init__.py"
done

touch tests/__init__.py tests/unit/__init__.py tests/integration/__init__.py tests/fixtures/__init__.py
```

### Phase 2: Move Files (With Testing)

```bash
# Copy (don't move yet) core modules
cp alert_manager.py src/wspma/core/
cp process_analyzer.py src/wspma/core/
cp service_auditor.py src/wspma/core/

# Copy utilities
cp path_utils.py src/wspma/utils/

# Copy configuration
cp config.py src/wspma/config/settings.py

# Copy reporting
cp report_generator.py src/wspma/reporting/

# Copy CLI
cp monitor_agent.py src/wspma/cli/agent.py

# Copy dependencies
cp demo_scenarios.py src/wspma/utils/

# Copy GUI (if applicable)
cp -r gui/ src/wspma/
```

### Phase 3: Update Imports

**Before:**
```python
import config
from alert_manager import AlertManager
from process_analyzer import ProcessAnalyzer
```

**After:**
```python
from wspma.config import settings
from wspma.core.alert_manager import AlertManager
from wspma.core.process_analyzer import ProcessAnalyzer
```

#### Mapping Table

| Old Import | New Import |
|-----------|-----------|
| `import config` | `from wspma.config import settings` |
| `from alert_manager import AlertManager` | `from wspma.core.alert_manager import AlertManager` |
| `from process_analyzer import ProcessAnalyzer` | `from wspma.core.process_analyzer import ProcessAnalyzer` |
| `from service_auditor import ServiceAuditor` | `from wspma.core.service_auditor import ServiceAuditor` |
| `from report_generator import ReportGenerator` | `from wspma.reporting.report_generator import ReportGenerator` |
| `from path_utils import ensure_alert_path_field` | `from wspma.utils.path_utils import ensure_alert_path_field` |

### Phase 4: Update __init__ Files

Create these __init__ files to expose public APIs:

**src/wspma/__init__.py**
```python
"""Windows Service Process Monitoring Agent."""

__version__ = "1.0.0"
__author__ = "Your Name"

from wspma.core.alert_manager import AlertManager
from wspma.core.process_analyzer import ProcessAnalyzer
from wspma.core.service_auditor import ServiceAuditor
from wspma.reporting.report_generator import ReportGenerator

__all__ = [
    "AlertManager",
    "ProcessAnalyzer",
    "ServiceAuditor",
    "ReportGenerator",
]
```

**src/wspma/core/__init__.py**
```python
"""Core monitoring engines."""

from wspma.core.alert_manager import AlertManager
from wspma.core.process_analyzer import ProcessAnalyzer
from wspma.core.service_auditor import ServiceAuditor

__all__ = ["AlertManager", "ProcessAnalyzer", "ServiceAuditor"]
```

**src/wspma/utils/__init__.py**
```python
"""Utility functions and helpers."""

from wspma.utils.path_utils import (
    ensure_alert_path_field,
    is_suspicious_path,
    resolve_alert_path,
)

__all__ = [
    "ensure_alert_path_field",
    "is_suspicious_path",
    "resolve_alert_path",
]
```

### Phase 5: Add Entry Point

Create **src/wspma/__main__.py**:
```python
"""CLI entry point for the monitoring agent."""

from wspma.cli.agent import main

if __name__ == "__main__":
    main()
```

Refactor **src/wspma/cli/agent.py** (renamed from monitor_agent.py):
```python
# At the end of the file, update:
if __name__ == "__main__":
    main()
```

Now users can run:
```bash
python -m wspma --help
python -m wspma --continuous --interval 120
```

### Phase 6: Create pyproject.toml

```toml
[build-system]
requires = ["setuptools>=45", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "windows-service-monitoring-agent"
version = "1.0.0"
description = "Blue-team oriented Windows Service & Process monitoring with SOC-friendly heuristics"
readme = "README.md"
requires-python = ">=3.9"
license = {text = "MIT"}
authors = [
    {name = "Your Name", email = "you@example.com"}
]
keywords = ["windows", "security", "monitoring", "process", "service"]

dependencies = [
    "psutil>=5.8.0",
    "colorama>=0.4.4",
    "PyYAML>=6.0",
]

[project.optional-dependencies]
gui = ["PyQt6>=6.0"]
dev = [
    "pytest>=7.0",
    "pytest-cov>=3.0",
    "black>=22.0",
    "flake8>=4.0",
    "mypy>=0.950",
    "isort>=5.10",
]

[project.scripts]
wspma = "wspma.cli.agent:main"

[tool.setuptools]
package-dir = {wspma = "src/wspma"}
```

### Phase 7: Update Configuration

Move detection rules to **config/detection_rules.yaml**:
```yaml
detection_rules:
  suspicious_relationships:
    critical:
      - parent: "winword.exe"
        children: ["powershell.exe", "cmd.exe", "wscript.exe"]
      - parent: "excel.exe"
        children: ["powershell.exe", "cmd.exe"]
  
  suspicious_paths:
    - "\\temp\\"
    - "\\downloads\\"
    - "\\appdata\\local\\temp"

severity_mappings:
  critical: 90
  high: 75
  medium: 50
  low: 30
  info: 10
```

Then load in **src/wspma/config/settings.py**:
```python
import yaml
import os

def load_detection_rules():
    """Load detection rules from YAML configuration."""
    config_path = os.path.join(os.path.dirname(__file__), '../../config/detection_rules.yaml')
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

# Load at module initialization
DETECTION_RULES = load_detection_rules()
```

### Phase 8: Testing & Validation

```bash
# 1. Install in development mode
pip install -e ".[dev]"

# 2. Run import validation
python -c "from wspma import AlertManager, ProcessAnalyzer, ServiceAuditor; print('✓ Imports OK')"

# 3. Run existing code to verify behavior
python -m wspma --help

# 4. Run tests
pytest tests/ -v --cov=src/wspma
```

### Phase 9: Cleanup (After Validation)

```bash
# Remove old files from root (after confirming new location works)
rm alert_manager.py
rm process_analyzer.py
rm service_auditor.py
rm monitor_agent.py
rm config.py
rm path_utils.py
rm report_generator.py

# Update .gitignore to exclude build artifacts
echo "build/" >> .gitignore
echo "dist/" >> .gitignore
echo "*.egg-info/" >> .gitignore
echo "__pycache__/" >> .gitignore
echo ".pytest_cache/" >> .gitignore
```

## Configuration File Locations

After migration, configurations should be in:

```
config/
├── detection_rules.yaml          # Detection heuristics
├── severity_mappings.json        # Severity levels
├── default_config.json           # Default settings
└── exclusions.txt                # Whitelisted processes
```

Load via:
```python
import yaml
import json
from pathlib import Path

config_dir = Path(__file__).parent.parent / "config"

def load_rules():
    with open(config_dir / "detection_rules.yaml") as f:
        return yaml.safe_load(f)

def load_defaults():
    with open(config_dir / "default_config.json") as f:
        return json.load(f)
```

## Testing Organization

```bash
tests/
├── unit/
│   ├── test_alert_manager.py      # Unit: AlertManager class
│   ├── test_process_analyzer.py   # Unit: ProcessAnalyzer class
│   ├── test_service_auditor.py    # Unit: ServiceAuditor class
│   └── test_detectors.py          # Unit: Detection functions
│
└── integration/
    ├── test_full_scan.py          # Integration: Full monitoring cycle
    └── test_baseline_drift.py      # Integration: Baseline comparison
```

## Benefits of This Structure

| Benefit | How It Helps |
|---------|------------|
| **Clear Ownership** | Each folder has a single responsibility (SRP) |
| **Easy Navigation** | New developers understand module organization |
| **Better Testing** | Components are more isolated and testable |
| **Distribution Ready** | Can publish to PyPI or create executables |
| **Scalability** | Adding new features doesn't require root changes |
| **IDE Support** | Better autocomplete and refactoring in IDEs |
| **CI/CD Ready** | Structure supports automated testing and builds |

## Timeline Estimate

| Phase | Duration | Effort |
|-------|----------|--------|
| Phase 1: Directory Setup | < 5 min | Trivial |
| Phase 2: Move Files | < 10 min | Trivial |
| Phase 3: Update Imports | 30-45 min | Medium (regex-based) |
| Phase 4-5: Entry Points | 15-20 min | Low |
| Phase 6-7: Config Files | 20-30 min | Low |
| Phase 8: Testing | 15-30 min | Medium |
| Phase 9: Cleanup | 5 min | Trivial |
| **TOTAL** | **~2 hours** | **Manageable** |

## Backwards Compatibility

To maintain backwards compatibility during transition:

```python
# Old-style import still works
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from wspma.core.alert_manager import AlertManager
# Users can still do: from alert_manager import AlertManager
# (Via symlink or compatibility layer)
```

---

**Next Step**: Run Phase 1 to create directory structure, then incrementally move files and test.
