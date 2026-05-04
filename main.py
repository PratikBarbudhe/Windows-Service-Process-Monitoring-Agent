from __future__ import annotations

from app.logging_setup import configure_logging
from cli.agent_cli import run_cli


def main() -> None:
    configure_logging()
    run_cli()


if __name__ == "__main__":
    main()

