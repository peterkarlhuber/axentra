"""Command line: ``python -m taskboard migrate | bootstrap | serve``.

Settings come from Axentra's configuration (``AXENTRA_CONFIG`` file + ``AXENTRA__*`` variables);
see ``examples/taskboard/taskboard.toml``.
"""

from __future__ import annotations

import argparse
import sys

from axentra.config.settings import load_settings
from axentra.platform import Axentra


def _ax() -> Axentra:
    from taskboard.app import taskboard_migrations

    ax = Axentra.from_settings(load_settings())
    ax.register_migrations(taskboard_migrations())
    return ax


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="taskboard")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("migrate", help="apply Axentra's and Taskboard's migrations (run as the schema owner)")
    sub.add_parser("bootstrap", help="create the tasks_created meter and the free/pro plans (idempotent)")
    serve = sub.add_parser("serve", help="run the HTTP server")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8090)
    args = parser.parse_args(argv)

    if args.command == "migrate":
        for name in _ax().migrate():
            print(f"applied {name}")
        return 0
    if args.command == "bootstrap":
        from taskboard.app import resolve_product_id
        from taskboard.service import TaskboardService

        ax = _ax()
        ax.start()
        try:
            TaskboardService(ax, resolve_product_id(ax)).bootstrap()
        finally:
            ax.close()
        print("taskboard: meter and plans are in place")
        return 0
    import uvicorn

    from taskboard.app import create_taskboard_app

    uvicorn.run(create_taskboard_app(), host=args.host, port=args.port, proxy_headers=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
