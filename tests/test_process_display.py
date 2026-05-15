from app.process_display import (
    attach_group_labels,
    normalize_cpu_percent,
    resolve_display_name,
    should_skip_high_cpu_alert,
)


def test_resolve_python_script_display_name() -> None:
    name = resolve_display_name(
        pid=1234,
        name="python.exe",
        exe=r"C:\Python311\python.exe",
        cmdline=[
            r"C:\Python311\python.exe",
            r"F:\Windows-Service-Process-Monitoring-Agent\dashboard\dashboard_streamlit.py",
        ],
        window_title=None,
    )
    assert name.startswith("dashboard_streamlit.py")


def test_group_label_counts() -> None:
    labels = attach_group_labels(["python.exe", "python.exe", "python.exe", "Code.exe"])
    assert labels.count("Python (3)") == 3
    assert labels[-1] == "Code"


def test_skip_idle_cpu_alert_only() -> None:
    assert should_skip_high_cpu_alert(name="System Idle Process", display_name="System Idle Process")
    assert not should_skip_high_cpu_alert(name="chrome.exe", display_name="Google Chrome")


def test_normalize_cpu_percent_matches_task_manager_scale(monkeypatch) -> None:
    monkeypatch.setattr("app.process_display.cpu_count_logical", lambda: 8)
    assert normalize_cpu_percent(101.4) == 12.68
    assert normalize_cpu_percent(800.0) == 100.0
    assert normalize_cpu_percent(-5.0) == 0.0


def test_skip_agent_stack_for_cpu_alerts() -> None:
    assert should_skip_high_cpu_alert(name="uvicorn.exe", display_name="uvicorn.exe")
    assert should_skip_high_cpu_alert(
        name="python.exe",
        display_name="dashboard_streamlit.py - dashboard",
    )


def test_python_inline_command_uses_friendly_name() -> None:
    name = resolve_display_name(
        pid=999,
        name="python.exe",
        exe=r"C:\Python311\python.exe",
        cmdline=[r"C:\Python311\python.exe", "-c", "print('hello')"],
        window_title=None,
    )
    assert name == "Python"
