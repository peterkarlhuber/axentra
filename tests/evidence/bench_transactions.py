"""Benchmark of scoped transactions (TABRION QA-25, MIG-T-AXE-9): overhead of a MIG-AXE step at most +5 %.

Document 07 (section 8.2) bounds the overhead of the Tabrion adoption: 1,000 ``Database.transaction()`` calls with a
tenant scope may take at most 5 % longer after a step than before. Timings depend on the machine, so the comparison is
an A/B run on one machine: the old commit and the new one, each measured with this tool, then compared::

    python -m tests.evidence.bench_transactions run --url <URL> --out old.json      # in a checkout of the old SHA
    python -m tests.evidence.bench_transactions run --url <URL> --out new.json      # in the step's checkout
    python -m tests.evidence.bench_transactions compare old.json new.json           # exit 1 above +5 %

``run`` opens an Axentra pool of one connection (as a deployment owns it, with ``statement_timeout`` configured) on
``URL`` (any database: no table is read), warms up, and times ``--rounds`` rounds of ``--calls`` transactions; each
transaction sets the tenant scope and runs ``SELECT 1``. The median round counts. Compare in the same environment
(same server, no other load), and repeat a run whose result is close to the limit.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import platform
import statistics
import sys
import time
from typing import Any

#: The overhead a step may add (document 07, section 8.2).
LIMIT = 0.05
PRODUCT_ID = "00000000-0000-4000-8000-000000000001"
TENANT_ID = "00000000-0000-4000-8000-000000000002"


def measure(url: str, *, calls: int = 1000, rounds: int = 7, warmup: int = 200) -> dict[str, Any]:
    """Time ``rounds`` rounds of ``calls`` scoped transactions; milliseconds per round."""
    from axentra.data.database import Database, DbScope

    scope = DbScope.tenant(PRODUCT_ID, TENANT_ID)
    db = Database(url, min_size=1, max_size=1)
    db.open()
    try:

        def one_round(n: int) -> float:
            start = time.perf_counter()
            for _ in range(n):
                with db.transaction(scope) as tx:
                    tx.scalar("SELECT 1")
            return (time.perf_counter() - start) * 1000.0

        one_round(warmup)
        timings = [one_round(calls) for _ in range(rounds)]
    finally:
        db.close()
    return {
        "calls": calls,
        "rounds": rounds,
        "round_ms": [round(t, 3) for t in timings],
        "median_ms": round(statistics.median(timings), 3),
        "min_ms": round(min(timings), 3),
        "python": platform.python_version(),
    }


def compare(old: dict[str, Any], new: dict[str, Any], limit: float = LIMIT) -> tuple[bool, float]:
    """Whether ``new`` stays within ``limit`` of ``old`` (median rounds), and the relative change."""
    if old["calls"] != new["calls"]:
        raise ValueError("the runs differ in --calls")
    change = new["median_ms"] / old["median_ms"] - 1.0
    return change <= limit + 1e-9, change  # exactly +5 % passes (float rounding)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m tests.evidence.bench_transactions", description=__doc__.split("\n")[0]
    )
    sub = parser.add_subparsers(dest="action", required=True)
    run = sub.add_parser("run", help="measure and print (or write) the result")
    run.add_argument("--url", required=True, help="a PostgreSQL URL (any database)")
    run.add_argument("--calls", type=int, default=1000)
    run.add_argument("--rounds", type=int, default=7)
    run.add_argument("--out", type=Path)
    cmp = sub.add_parser("compare", help="compare two results; exit 1 above the limit")
    cmp.add_argument("old", type=Path)
    cmp.add_argument("new", type=Path)
    cmp.add_argument("--limit", type=float, default=LIMIT)
    args = parser.parse_args(argv)
    if args.action == "run":
        result = measure(args.url, calls=args.calls, rounds=args.rounds)
        text = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.out:
            args.out.write_text(text, "utf-8")
        sys.stdout.write(text)
        return 0
    ok, change = compare(
        json.loads(args.old.read_text("utf-8")), json.loads(args.new.read_text("utf-8")), args.limit
    )
    print(f"median change {change:+.1%} (limit +{args.limit:.0%}): {'ok' if ok else 'too slow'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
