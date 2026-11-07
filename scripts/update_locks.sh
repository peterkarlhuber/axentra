#!/usr/bin/env bash
# Regenerate the hash-pinned locks of the container image from pyproject.toml and deploy/constraints.txt.
# Needs uv (https://docs.astral.sh/uv/). Run after changing dependencies or deploy/constraints.txt, then
# commit deploy/locks/*.txt together with that change (CI runs scripts/check_locks.py).
set -euo pipefail
cd "$(dirname "$0")/.."
common=(--python-version 3.13 --python-platform x86_64-manylinux_2_28 --no-header --no-annotate --generate-hashes --quiet)
uv pip compile pyproject.toml --extra server -c deploy/constraints.txt "${common[@]}" -o deploy/locks/server.txt
uv pip compile pyproject.toml --extra server --extra oidc --extra s3 --extra otel -c deploy/constraints.txt \
  "${common[@]}" -o deploy/locks/full.txt
uv pip compile deploy/locks/build.in "${common[@]}" -o deploy/locks/build.txt
python3 scripts/check_locks.py
