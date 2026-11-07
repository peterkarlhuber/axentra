#!/usr/bin/env python3
"""Generate the sync client from the async one (the single source of truth).

    python scripts/unasync.py           # write src/axentra_client/_sync/client.py
    python scripts/unasync.py --check   # exit 1 when the generated file is stale

The transformation is purely textual (like httpcore's unasync): ``async def`` -> ``def``,
``await x`` -> ``x``, ``async for/with`` -> ``for/with``, ``AsyncFoo`` -> ``Foo``, and the
``a``-prefixed httpx methods (``aclose``, ``aread``, ``aiter_bytes``) -> their sync names.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "src/axentra_client/_async/client.py"
TARGET = ROOT / "src/axentra_client/_sync/client.py"

HEADER = "# Generated from _async/client.py by scripts/unasync.py. Do not edit; edit the async source.\n"

SUBS: list[tuple[str, str]] = [
    (r"\basynccontextmanager\b", "contextmanager"),
    (r"\basync def\b", "def"),
    (r"\basync with\b", "with"),
    (r"\basync for\b", "for"),
    (r"\bawait ", ""),
    (r"\b__aenter__\b", "__enter__"),
    (r"\b__aexit__\b", "__exit__"),
    (r"\baclose\b", "close"),
    (r"\baread\b", "read"),
    (r"\baiter_bytes\b", "iter_bytes"),
    (r"\baiter_raw\b", "iter_raw"),
    (r"\baiter_lines\b", "iter_lines"),
    (r"\bAsync([A-Z]\w*)", r"\1"),
    (r"\b_async\b", "_sync"),
    (r"\bAsyncIterator\b", "Iterator"),
]

SYNC_DOCSTRING = '''"""The synchronous Axentra client.

Generated from ``axentra_client/_async/client.py`` by ``scripts/unasync.py``; edit the async
source and regenerate. See that module for how to add endpoints.
"""'''


def transform(text: str) -> str:
    start = text.index('"""')
    end = text.index('"""', start + 3) + 3
    body = text[end:]
    for pattern, repl in SUBS:
        body = re.sub(pattern, repl, body)
    text = text[:start] + SYNC_DOCSTRING + body
    return HEADER + text


def main(argv: list[str]) -> int:
    out = transform(SOURCE.read_text(encoding="utf-8"))
    current = TARGET.read_text(encoding="utf-8") if TARGET.exists() else None
    if "--check" in argv:
        if current != out:
            print(f"{TARGET.relative_to(ROOT)} is stale; run `python scripts/unasync.py`", file=sys.stderr)
            return 1
        print(f"{TARGET.relative_to(ROOT)} is up to date")
        return 0
    if current != out:
        TARGET.write_text(out, encoding="utf-8")
        print(f"wrote {TARGET.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
