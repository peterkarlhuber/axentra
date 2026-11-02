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


def _load_modules(ax, names: list[str] | None) -> None:  # type: ignore[no-untyped-def]
    """Import product modules; ``def setup(ax)`` is called if present (handlers, encrypted columns)."""
    import importlib

    for name in names or []:
        mod = importlib.import_module(name)
        setup = getattr(mod, "setup", None)
        if callable(setup):
            setup(ax)


def cmd_migrate(args: argparse.Namespace) -> int:
    ax = _ax(args)
    _load_modules(ax, args.load)
    done = ax.migrate(allow_newer=args.allow_newer)
    out: dict[str, object] = {"applied": done}
    if args.grant_runtime_role:
        from axentra.data.roles import grant_runtime_role
        from axentra.platform import _migration_url

        out["runtime_role"] = grant_runtime_role(
            _migration_url(ax.settings), args.grant_runtime_role
        ).as_dict()
    print(json.dumps(out))
    return 0


def cmd_migrate_status(args: argparse.Namespace) -> int:
    ax = _ax(args)
    _load_modules(ax, args.load)
    print(json.dumps(ax.migration_runner().status(), indent=2))
    return 0


def cmd_migrate_check(args: argparse.Namespace) -> int:
    """Exit 0 when the schema matches the code, 3 when migrations are pending or unknown."""
    ax = _ax(args)
    _load_modules(ax, args.load)
    result = ax.migration_runner().check(args.namespace or None)
    print(json.dumps(result.as_dict(), indent=2))
    return 0 if result.current else 3


def cmd_db_grant_runtime_role(args: argparse.Namespace) -> int:
    """Grant the runtime role data access to the schema, as the owner (migration) role; idempotent."""
    from axentra.config.settings import load_settings
    from axentra.data.roles import grant_runtime_role
    from axentra.platform import _migration_url

    report = grant_runtime_role(_migration_url(load_settings(args.config)), args.role, schema=args.schema)
    print(json.dumps(report.as_dict(), indent=2))
    return 0 if report.connect else 2


def cmd_db_inspect_role(args: argparse.Namespace) -> int:
    """Show how row-level security applies to a role; exit 3 when it is not restricted."""
    import psycopg

    from axentra.config.settings import load_settings
    from axentra.data.roles import inspect_role
    from axentra.platform import _database_url, _migration_url

    settings = load_settings(args.config)
    with psycopg.connect(_migration_url(settings), autocommit=True) as conn:
        role = args.role
        if role is None:
            with psycopg.connect(_database_url(settings), autocommit=True) as app:
                row = app.execute("SELECT current_user").fetchone()
                role = str(row[0]) if row else ""
        report = inspect_role(conn, role, args.schema)
    print(json.dumps(report.as_dict(), indent=2))
    return 0 if report.restricted else 3


def cmd_secrets_reencrypt(args: argparse.Namespace) -> int:
    """Re-encrypt stored ciphertexts with the active key (exit 2 if any value could not be read)."""
    from axentra.audit.logging import configure_logging

    ax = _ax(args)
    configure_logging(ax.settings.observability.log_level, ax.settings.observability.log_format)
    _load_modules(ax, args.load)
    ax.db.open()
    try:
        report = ax.reencrypt_secrets(dry_run=args.dry_run, batch_size=args.batch_size)
    finally:
        ax.close()
    print(json.dumps(report.as_dict(), indent=2))
    return 2 if report.failed else 0


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


def cmd_worker(args: argparse.Namespace) -> int:
    """Run a job worker (also fires schedules and purges old jobs while it is the leader)."""
    import signal

    from axentra.audit.logging import configure_logging
    from axentra.events.worker import JobWorker

    ax = _ax(args)
    configure_logging(ax.settings.observability.log_level, ax.settings.observability.log_format)
    if not ax.settings.module_enabled("events"):
        print("the events module is disabled (settings.modules)", file=sys.stderr)
        return 1
    ax.start()
    _load_modules(ax, args.load)
    kinds = [k.strip() for k in args.kinds.split(",") if k.strip()] if args.kinds else None
    worker = JobWorker(ax, kinds=kinds, concurrency=args.concurrency, scheduler=not args.no_scheduler)
    try:
        if args.once:
            print(json.dumps({"processed": worker.run_once()}))
            return 0

        def _stop(signum: int, frame: object) -> None:
            worker.stop(timeout=args.shutdown_timeout)

        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)
        worker._stop_timeout = args.shutdown_timeout
        worker.run()
        return 0
    finally:
        ax.close()


def cmd_generate_key(args: argparse.Namespace) -> int:
    from axentra.config.secrets import generate_key

    print(f"{args.kid}:{generate_key()}")
    return 0


def cmd_notify_dispatch(args: argparse.Namespace) -> int:
    import signal
    import threading

    from axentra.audit.logging import configure_logging

    ax = _ax(args)
    configure_logging(ax.settings.observability.log_level, ax.settings.observability.log_format)
    if ax.notify is None:
        print("the notify module is not enabled", file=sys.stderr)
        return 1
    ax.start()
    try:
        dispatcher = ax.notify.dispatcher()
        if not args.loop:
            res = dispatcher.run_once(args.batch)
            print(json.dumps({k: v for k, v in vars(res).items() if k != "message_ids"}))
            return 0
        stop = threading.Event()
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
        signal.signal(signal.SIGINT, lambda *_: stop.set())
        dispatcher.run_loop(batch=args.batch, interval=args.interval, stop=stop)
        return 0
    finally:
        ax.close()


def cmd_maintenance_purge(args: argparse.Namespace) -> int:
    from axentra.observability.maintenance import run_maintenance

    ax = _ax(args)
    ax.db.open()
    try:
        report = run_maintenance(ax)
    finally:
        ax.close()
    print(json.dumps(report, default=str))
    return 1 if report.get("errors") else 0


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
    m.add_argument(
        "--check",
        action="store_true",
        help="compare schema and code per namespace (pending/unknown versions); exit 3 if not current",
    )
    m.add_argument("--namespace", action="append", help="with --check: only these namespaces")
    m.add_argument(
        "--allow-newer",
        action="store_true",
        help="apply even when the database has migrations this code does not know",
    )
    m.add_argument(
        "--load",
        action="append",
        metavar="MODULE",
        help="import a module that registers migrations (setup(ax))",
    )
    m.add_argument(
        "--grant-runtime-role",
        metavar="ROLE",
        help="afterwards, grant this runtime role data access (as `axentra db grant-runtime-role`)",
    )
    m.set_defaults(
        func=lambda a: (
            cmd_migrate_check(a) if a.check else cmd_migrate_status(a) if a.status else cmd_migrate(a)
        )
    )

    d = sub.add_parser("db", help="database role tasks (run as the owner role: database.migration_url_ref)")
    dsub = d.add_subparsers(dest="db_command", required=True)
    gr = dsub.add_parser(
        "grant-runtime-role",
        help="grant a runtime role (no superuser, no BYPASSRLS, owns nothing) data access to the schema, idempotent",
    )
    gr.add_argument("role")
    gr.add_argument("--schema", help="default: the owner connection's current schema")
    gr.set_defaults(func=cmd_db_grant_runtime_role)
    ir = dsub.add_parser(
        "inspect-role", help="show whether row-level security applies to a role; exit 3 if not"
    )
    ir.add_argument("role", nargs="?", help="default: the role of database.url")
    ir.add_argument("--schema")
    ir.set_defaults(func=cmd_db_inspect_role)

    w = sub.add_parser("worker", help="run a background job worker (jobs, schedules, webhooks)")
    w.add_argument("--kinds", help="comma-separated job kinds (default: every registered kind)")
    w.add_argument("--concurrency", type=int, default=4)
    w.add_argument("--once", action="store_true", help="run due jobs, then exit")
    w.add_argument("--no-scheduler", action="store_true", help="never fire schedules in this worker")
    w.add_argument("--shutdown-timeout", type=float, default=30.0, help="seconds to wait for running jobs")
    w.add_argument(
        "--load",
        action="append",
        metavar="MODULE",
        help="import a module that registers handlers (setup(ax))",
    )
    w.set_defaults(func=cmd_worker)

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
    nd = sub.add_parser("notify-dispatch", help="deliver queued notifications")
    mode = nd.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true", help="one batch, then exit (default)")
    mode.add_argument("--loop", action="store_true", help="run until SIGTERM/SIGINT")
    nd.add_argument("--batch", type=int, default=20)
    nd.add_argument("--interval", type=float, default=2.0, help="idle sleep in seconds (--loop)")
    nd.set_defaults(func=cmd_notify_dispatch)

    mt = sub.add_parser("maintenance", help="maintenance tasks")
    mtsub = mt.add_subparsers(dest="maintenance_command", required=True)
    pg = mtsub.add_parser("purge", help="audit retention, expired sessions, notification retention")
    pg.set_defaults(func=cmd_maintenance_purge)

    k = sub.add_parser("keys", help="encryption keyring tasks")
    ksub = k.add_subparsers(dest="keys_command", required=True)
    g = ksub.add_parser("generate", help="print a new keyring entry kid:base64key")
    g.add_argument("--kid", default="k1")
    g.set_defaults(func=cmd_generate_key)

    sc = sub.add_parser("secrets", help="stored secret tasks")
    scsub = sc.add_subparsers(dest="secrets_command", required=True)
    re_ = scsub.add_parser("reencrypt", help="re-encrypt stored values with the active key (key rotation)")
    re_.add_argument("--dry-run", action="store_true", help="only report counts per column and key id")
    re_.add_argument("--batch-size", type=int, default=500)
    re_.add_argument(
        "--load",
        action="append",
        metavar="MODULE",
        help="import a module whose setup(ax) registers encrypted columns",
    )
    re_.set_defaults(func=cmd_secrets_reencrypt)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
