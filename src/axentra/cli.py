"""The ``axentra`` command line: serve, migrate, workers, admin and OpenAPI tasks."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from axentra import __version__


def _ax(args: argparse.Namespace):  # type: ignore[no-untyped-def]
    from axentra.config.settings import load_settings
    from axentra.platform import Axentra

    return Axentra.from_settings(load_settings(args.config))


def cmd_migrate(args: argparse.Namespace) -> int:
    ax = _ax(args)
    done = ax.migrate()
    print(json.dumps({"applied": done}))
    return 0


def cmd_migrate_status(args: argparse.Namespace) -> int:
    from axentra.data.migrations import MigrationRunner

    ax = _ax(args)
    runner = MigrationRunner(ax.settings.database.migration_url or ax.db.url)
    print(json.dumps(runner.status(), indent=2))
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from axentra.api.app import create_app
    from axentra.audit.logging import configure_logging

    ax = _ax(args)
    configure_logging(ax.settings.observability.log_level, ax.settings.observability.log_format)
    if args.migrate:
        ax.migrate()
    app = create_app(axentra=ax)
    # Proxy headers are handled by Axentra itself (security.trusted_proxies), not by uvicorn.
    uvicorn.run(
        app, host=args.host, port=args.port, proxy_headers=False, server_header=False, access_log=False
    )
    return 0


def cmd_setup_token(args: argparse.Namespace) -> int:
    ax = _ax(args)
    ax.db.open()
    if not ax.identity.setup_required() and not args.force:
        print("setup is already complete (a platform admin exists)", file=sys.stderr)
        return 1
    print(ax.identity.create_setup_token())
    return 0


def cmd_openapi(args: argparse.Namespace) -> int:
    from axentra.api.app import create_app
    from axentra.config.settings import load_settings

    settings = load_settings(None, environ={}, environment="test", mode="multi")
    app = create_app(settings, start=False)
    spec = app.openapi()
    text = json.dumps(spec, indent=2, sort_keys=True) + "\n"
    if args.check:
        current = Path(args.output).read_text(encoding="utf-8") if Path(args.output).exists() else ""
        if current != text:
            print(f"{args.output} is out of date; run `axentra openapi export`", file=sys.stderr)
            return 1
        print(f"{args.output} is up to date")
        return 0
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(text, encoding="utf-8")
    print(f"wrote {args.output}")
    return 0


def cmd_storage_purge(args: argparse.Namespace) -> int:
    ax = _ax(args)
    if ax.storage is None:
        print("the storage module is not enabled", file=sys.stderr)
        return 1
    ax.db.open()
    try:
        report = ax.storage.purge(orphans=not args.no_orphans, retain_deleted_days=args.retain_deleted_days)
    finally:
        ax.close()
    print(report.model_dump_json())
    return 0 if report.errors == 0 else 2


def cmd_generate_key(args: argparse.Namespace) -> int:
    from axentra.config.secrets import generate_key

    print(f"{args.kid}:{generate_key()}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="axentra", description="Axentra SaaS backend foundation")
    p.add_argument("--version", action="version", version=f"axentra {__version__}")
    p.add_argument("--config", help="TOML configuration file (default: $AXENTRA_CONFIG)")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("serve", help="run the HTTP API")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    s.add_argument("--migrate", action="store_true", help="apply migrations before serving")
    s.set_defaults(func=cmd_serve)

    m = sub.add_parser("migrate", help="apply database migrations")
    m.add_argument("--status", action="store_true", help="only show the migration status")
    m.set_defaults(func=lambda a: cmd_migrate_status(a) if a.status else cmd_migrate(a))

    a = sub.add_parser("admin", help="administration tasks")
    asub = a.add_subparsers(dest="admin_command", required=True)
    st = asub.add_parser("setup-token", help="create a one-time token to register the first platform admin")
    st.add_argument("--force", action="store_true")
    st.set_defaults(func=cmd_setup_token)

    o = sub.add_parser("openapi", help="OpenAPI contract tasks")
    osub = o.add_subparsers(dest="openapi_command", required=True)
    ex = osub.add_parser("export", help="write the OpenAPI document")
    ex.add_argument("--output", default="openapi/axentra-v1.json")
    ex.add_argument("--check", action="store_true", help="fail if the committed document differs")
    ex.set_defaults(func=cmd_openapi)

    sp = sub.add_parser("storage", help="file storage tasks")
    spsub = sp.add_subparsers(dest="storage_command", required=True)
    pu = spsub.add_parser("purge", help="expire files, discard abandoned uploads, delete orphaned objects")
    pu.add_argument("--no-orphans", action="store_true", help="skip the backend scan for orphaned objects")
    pu.add_argument("--retain-deleted-days", type=int, default=30)
    pu.set_defaults(func=cmd_storage_purge)

    k = sub.add_parser("keys", help="encryption keyring tasks")
    ksub = k.add_subparsers(dest="keys_command", required=True)
    g = ksub.add_parser("generate", help="print a new keyring entry kid:base64key")
    g.add_argument("--kid", default="k1")
    g.set_defaults(func=cmd_generate_key)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
