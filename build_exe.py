"""Build a standalone Windows executable for the monitoring agent."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parent
    script = root / "monitor_agent.py"
    if not script.exists():
        raise SystemExit("monitor_agent.py not found")

    distdir = root / "dist"
    builddir = root / "build"
    specfile = root / "monitor_agent.spec"

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--onefile",
        "--name",
        "monitor-agent",
        "--distpath",
        str(distdir),
        "--workpath",
        str(builddir),
        "--specpath",
        str(root),
        str(script),
    ]

    print("Building executable with PyInstaller...")
    print("Command:", " ".join(cmd))
    result = subprocess.run(cmd)
    if result.returncode != 0:
        raise SystemExit(f"Build failed with exit code {result.returncode}")

    exe_path = distdir / "monitor-agent.exe"
    if exe_path.exists():
        print(f"Build succeeded: {exe_path}")
    else:
        raise SystemExit("Build completed but executable was not found")


if __name__ == "__main__":
    main()
