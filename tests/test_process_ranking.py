from app.process_ranking import rank_top_processes


def test_rank_top_by_cpu() -> None:
    processes = [
        {"pid": 1, "display_name": "a", "cpu_percent": 5.0, "memory_mb": 100},
        {"pid": 2, "display_name": "b", "cpu_percent": 50.0, "memory_mb": 200},
        {"pid": 3, "display_name": "c", "cpu_percent": 25.0, "memory_mb": 50},
    ]
    top = rank_top_processes(processes, sort_by="cpu", limit=2)
    assert [row["pid"] for row in top] == [2, 3]
    assert top[0]["rank"] == 1


def test_rank_top_by_memory() -> None:
    processes = [
        {"pid": 1, "display_name": "a", "cpu_percent": 5.0, "memory_mb": 900},
        {"pid": 2, "display_name": "b", "cpu_percent": 50.0, "memory_mb": 200},
    ]
    top = rank_top_processes(processes, sort_by="memory", limit=1)
    assert top[0]["pid"] == 1
