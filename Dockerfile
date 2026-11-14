# syntax=docker/dockerfile:1
# Axentra API container image.
#
#   docker build -t axentra:local .
#   docker build --build-arg EXTRAS=server,oidc,s3,otel -t axentra:full .
#
# Every installed distribution is pinned by version AND hash (pip --require-hashes): the runtime
# dependencies from deploy/locks/server.txt (EXTRAS=server) or deploy/locks/full.txt (any other
# EXTRAS), the build backend (hatchling) from deploy/locks/build.txt, and Tabrion, which is not on a
# package index, as the source archive of its pinned commit from deploy/locks/tabrion.txt (built offline
# like Axentra's own wheel). Regenerate them with scripts/update_locks.sh. The image carries a CycloneDX
# SBOM at /opt/axentra/sbom.cdx.json.
# The image runs as an unprivileged user (uid/gid 10001) and contains no compiler or build tools.

# The base is pinned by digest in each FROM line (Dependabot's docker ecosystem keeps both current).

# --- build: install Axentra and its pinned dependencies into a self-contained venv -------------
FROM python:3.13-slim@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb AS build
# Reproducible builds: with --build-arg SOURCE_DATE_EPOCH=<commit time> pip compiles the .pyc files with
# hash-based invalidation (no source mtime in their headers), so two builds of one commit give identical
# layers when the output also uses rewrite-timestamp=true. Without the argument the build is unchanged.
ARG SOURCE_DATE_EPOCH
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1
RUN python -m venv /opt/axentra && python -m venv /opt/build
WORKDIR /src
COPY deploy/locks deploy/locks
COPY deploy/sbom.py deploy/sbom.py
# The wheel of Axentra itself is built offline (no build isolation) with the hash-pinned backend,
# in a separate venv that does not reach the image.
RUN /opt/build/bin/pip install --require-hashes --no-deps -r deploy/locks/build.txt \
    && /opt/build/bin/pip wheel --require-hashes --no-deps --no-build-isolation -w /tmp/wheels \
       -r deploy/locks/tabrion.txt
COPY pyproject.toml README.md LICENSE CHANGELOG.md NOTICE.md ./
COPY src ./src
RUN /opt/build/bin/pip wheel --no-deps --no-build-isolation --no-index -w /tmp/wheels /src
ARG EXTRAS=server
# pip check fails when the chosen lock lacks a dependency of the requested extras. The installed Tabrion must be the
# wheel built here from the hashed archive, never one from a package index (dependency confusion, TABRION DC-AX-1).
RUN lock=deploy/locks/full.txt; if [ "${EXTRAS}" = "server" ]; then lock=deploy/locks/server.txt; fi \
    && /opt/axentra/bin/pip install --require-hashes --no-deps -r "${lock}" \
    && /opt/axentra/bin/pip install --no-deps --no-index "$(ls /tmp/wheels/tabrion-*.whl)" \
    && /opt/axentra/bin/pip install --no-deps --no-index "$(ls /tmp/wheels/axentra-*.whl)[${EXTRAS}]" \
    && /opt/axentra/bin/pip check \
    && /opt/axentra/bin/python -I -c 'import json, importlib.metadata as m; d = json.loads(m.distribution("tabrion").read_text("direct_url.json") or "null"); assert d and "archive_info" in d and d["url"].startswith("file:///tmp/wheels/tabrion-"), d' \
    && /opt/axentra/bin/axentra --version \
    && /opt/axentra/bin/python -I deploy/sbom.py --component axentra > /opt/axentra/sbom.cdx.json \
    && /opt/axentra/bin/python -m pip uninstall --yes --quiet pip

# --- runtime ------------------------------------------------------------------------------------
FROM python:3.13-slim@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb AS runtime
LABEL org.opencontainers.image.title="Axentra" \
      org.opencontainers.image.description="Modular SaaS backend foundation (HTTP API)" \
      org.opencontainers.image.source="https://github.com/peterkarlhuber/axentra" \
      org.opencontainers.image.licenses="LicenseRef-Proprietary"
# The server needs no package installer: pip (with its vendored urllib3, msgpack and setuptools, flagged by image
# scans) and ensurepip's bundled wheel are removed from the base image; the app venv drops its pip in the build stage.
# `pip check` runs in the build stage, before the removal.
RUN rm -rf /usr/local/lib/python3.13/site-packages/pip /usr/local/lib/python3.13/site-packages/pip-*.dist-info \
       /usr/local/lib/python3.13/ensurepip /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.13 \
    && ! python -c "import pip" 2>/dev/null \
    && groupadd --system --gid 10001 axentra \
    && useradd --system --uid 10001 --gid axentra --home-dir /var/lib/axentra --create-home \
       --shell /usr/sbin/nologin axentra \
    && install -d -o axentra -g axentra -m 0750 /var/lib/axentra/var
COPY --from=build /opt/axentra /opt/axentra
# The image is a server: production checks by default (B-03). `serve` binds 0.0.0.0, so the settings'
# loopback check for an unset environment cannot see that the container is reachable. A local trial
# sets AXENTRA__ENVIRONMENT=development explicitly (deploy/compose/.env.example does).
ENV PATH=/opt/axentra/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    AXENTRA__ENVIRONMENT=production
# Relative paths in the configuration (e.g. storage.local_path = "./var/storage") resolve here.
WORKDIR /var/lib/axentra
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/v1/health/live', timeout=4).status == 200 else 1)"]
# Default command: `axentra serve --host 0.0.0.0 --port 8080`. Other commands replace CMD,
# e.g. `docker run ... axentra:local migrate` or `... admin setup-token`.
ENTRYPOINT ["axentra"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
