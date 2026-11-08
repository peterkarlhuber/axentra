"""Benchmark of scoped transactions (TABRION QA-25, MIG-T-AXE-9): overhead of a MIG-AXE step at most +5 %.

Document 07 (section 8.2) bounds the overhead of the Tabrion adoption: 1,000 ``Database.transaction()`` calls with a
tenant scope may take at most 5 % longer after a step than before. Single runs of the same code on one server differ
by far more than 5 % (review ``qa-13-25-review.md``, M-5: medians of 369 to 695 ms for identical code), so a result
is only valid as an **interleaved A/B comparison**: old and new code measured alternately in one job, on an idle
machine (not a shared CI or lane server), and judged by the median of the per-pair ratios::

    python -m tests.evidence.bench_transactions ab --url <URL> --old <old checkout> --new <new checkout> --out ab.json

``ab`` runs ``--pairs`` pairs (default 10). Each pair measures both sides in fresh processes, the order alternating
(AB, BA, AB, ...) so a drift of the machine hits both sides alike. A side is a checkout whose ``src`` is put first on
``PYTHONPATH``; the measuring code is this file, so the old checkout needs no copy of it. Each measurement opens an
Axentra pool of one connection (as a deployment owns it, with ``statement_timeout`` configured) on ``URL`` (any
database: no table is read), warms up and times ``--rounds`` rounds of ``--calls`` transactions; each transaction sets
the tenant scope and runs ``SELECT 1``; the median round is the measurement. The ratio of a pair is new / old.

The verdict (:func:`verdict`), from the median ``m`` and the quartiles ``q1``, ``q3`` of the ratios:

- ``too_noisy`` when ``q3 - q1 > 0.05``: the pairs scatter more than the bound itself; the result says nothing;
- ``ok`` when ``q3 <= 1.05``: three quarters of the pairs are within the bound;
- ``too_slow`` when ``q1 > 1.05``: three quarters of the pairs are above it;
- ``inconclusive`` otherwise (the bound lies between the quartiles).

Exit codes: 0 ``ok``, 1 ``too_slow``, 2 ``too_noisy`` or ``inconclusive``. Repeat an exit-2 result at most twice more
(three ``ab`` runs in all) on an idle machine; if none is ``ok`` or ``too_slow``, the pull request reports the
benchmark as inconclusive with the three files and states no performance result. **No TABRION MIG-AXE pull request may
state a performance result (within or above +5 %) without an ``ab`` file of this tool attached or linked.**

``run`` measures one side once (for a quick look; it is not a comparison).
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time
from typing import Any

#: The overhead a step may add (document 07, section 8.2).
LIMIT = 0.05
#: Pairs whose interquartile range of the ratios exceeds this are too noisy to judge.
NOISE = 0.05
PRODUCT_ID = "00000000-0000-4000-8000-000000000001"
TENANT_ID = "00000000-0000-4000-8000-000000000002"
EXIT = {"ok": 0, "too_slow": 1, "too_noisy": 2, "inconclusive": 2}


def measure(url: str, *, calls: int = 1000, rounds: int = 7, warmup: int = 200) -> dict[str, Any]:
    """Time ``rounds`` rounds of ``calls`` scoped transactions; milliseconds per round."""
    import axentra
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
        "axentra": str(Path(axentra.__file__).resolve().parent),
    }


def quartiles(values: list[float]) -> tuple[float, float, float]:
    """``(q1, median, q3)`` (inclusive method; one value is its own quartiles)."""
    if len(values) == 1:
        return values[0], values[0], values[0]
    q1, median, q3 = statistics.quantiles(values, n=4, method="inclusive")
    return q1, median, q3


def verdict(ratios: list[float], limit: float = LIMIT, noise: float = NOISE) -> str:
    """``ok``, ``too_slow``, ``too_noisy`` or ``inconclusive`` for the new/old ratios of the pairs (module docstring)."""
    if not ratios:
        raise ValueError("no pairs")
    q1, _, q3 = quartiles(sorted(ratios))
    bound = 1.0 + limit + 1e-9  # exactly +5 % passes (float rounding)
    if q3 - q1 > noise + 1e-9:
        return "too_noisy"
    if q3 <= bound:
        return "ok"
    if q1 > bound:
        return "too_slow"
    return "inconclusive"


def _measure_side(checkout: Path, url: str, calls: int, rounds: int, warmup: int) -> dict[str, Any]:
    """One measurement in a fresh process with ``checkout/src`` first on the path."""
    env = dict(
        os.environ, PYTHONPATH=os.pathsep.join([str(checkout / "src"), os.environ.get("PYTHONPATH", "")])
    )
    out = subprocess.run(
        [sys.executable, "-u", __file__, "run", "--url", url, "--calls", str(calls),
         "--rounds", str(rounds), "--warmup", str(warmup)],
        env=env, check=True, capture_output=True, text=True, cwd=checkout,
    )  # fmt: skip
    result: dict[str, Any] = json.loads(out.stdout)
    expected = (checkout / "src" / "axentra").resolve()
    if Path(result["axentra"]) != expected:
        raise RuntimeError(f"measured {result['axentra']}, not {expected}")
    return result


def ab(
    url: str, old: Path, new: Path, *, pairs: int = 10, calls: int = 1000, rounds: int = 5, warmup: int = 200
) -> dict[str, Any]:
    """Interleaved A/B comparison of two checkouts (module docstring)."""
    runs: list[dict[str, Any]] = []
    for i in range(pairs):
        order = ("old", "new") if i % 2 == 0 else ("new", "old")
        pair: dict[str, Any] = {"order": list(order)}
        for side in order:
            pair[side] = _measure_side(old if side == "old" else new, url, calls, rounds, warmup)["median_ms"]
        pair["ratio"] = round(pair["new"] / pair["old"], 4)
        runs.append(pair)
    ratios = [p["ratio"] for p in runs]
    q1, median, q3 = quartiles(sorted(ratios))
    return {
        "calls": calls,
        "rounds": rounds,
        "pairs": runs,
        "ratio_q1": round(q1, 4),
        "ratio_median": round(median, 4),
        "ratio_q3": round(q3, 4),
        "limit": LIMIT,
        "noise": NOISE,
        "verdict": verdict(ratios),
        "old": str(old.resolve()),
        "new": str(new.resolve()),
        "python": platform.python_version(),
        "machine": platform.machine(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m tests.evidence.bench_transactions", description=(__doc__ or "").split("\n")[0]
    )
    sub = parser.add_subparsers(dest="action", required=True)
    run = sub.add_parser("run", help="measure the installed or PYTHONPATH code once (not a comparison)")
    run.add_argument("--url", required=True, help="a PostgreSQL URL (any database)")
    run.add_argument("--calls", type=int, default=1000)
    run.add_argument("--rounds", type=int, default=7)
    run.add_argument("--warmup", type=int, default=200)
    run.add_argument("--out", type=Path)
    cmp = sub.add_parser(
        "ab", help="interleaved A/B comparison of two checkouts; exit 0 ok, 1 too slow, 2 unclear"
    )
    cmp.add_argument("--url", required=True, help="a PostgreSQL URL (any database)")
    cmp.add_argument("--old", type=Path, required=True, help="checkout of the old commit")
    cmp.add_argument("--new", type=Path, required=True, help="checkout of the step's commit")
    cmp.add_argument("--pairs", type=int, default=10)
    cmp.add_argument("--calls", type=int, default=1000)
    cmp.add_argument("--rounds", type=int, default=5)
    cmp.add_argument("--warmup", type=int, default=200)
    cmp.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    if args.action == "run":
        result = measure(args.url, calls=args.calls, rounds=args.rounds, warmup=args.warmup)
    else:
        result = ab(
            args.url,
            args.old,
            args.new,
            pairs=args.pairs,
            calls=args.calls,
            rounds=args.rounds,
            warmup=args.warmup,
        )
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.write_text(text, "utf-8")
    sys.stdout.write(text)
    if args.action == "ab":
        print(
            f"median ratio {result['ratio_median']:.3f} (quartiles {result['ratio_q1']:.3f}..{result['ratio_q3']:.3f},"
            f" limit {1 + LIMIT:.2f}): {result['verdict']}",
            file=sys.stderr,
        )
        return EXIT[result["verdict"]]
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
