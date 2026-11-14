# syntax=docker/dockerfile:1
# Taskboard container image (demo). Build from the repository root:
#
#   docker build -f examples/taskboard/Dockerfile -t taskboard:local .
#
# Installs Axentra from this repository (pinned by deploy/constraints.txt) plus the Taskboard
# package; runs as an unprivileged user like the Axentra image. Tabrion is not on a package index:
# it comes first, built offline (no build isolation) from the hash-pinned source archive of
# deploy/locks/tabrion.txt with the hash-pinned hatchling of deploy/locks/build.txt, in a separate venv. The build
# fails unless the installed Tabrion is that wheel (not one from a package index, TABRION DC-AX-1).

# The base is pinned by digest in each FROM line (Dependabot's docker ecosystem keeps both current).

FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS build
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1
RUN python -m venv /opt/taskboard && python -m venv /opt/build
WORKDIR /src
COPY deploy/constraints.txt deploy/constraints.txt
COPY deploy/locks/tabrion.txt deploy/locks/tabrion.txt
COPY deploy/locks/build.txt deploy/locks/build.txt
COPY pyproject.toml README.md LICENSE CHANGELOG.md NOTICE.md ./
COPY src ./src
COPY examples/taskboard ./examples/taskboard
RUN /opt/build/bin/pip install --require-hashes --no-deps -r deploy/locks/build.txt \
    && /opt/build/bin/pip wheel --require-hashes --no-deps --no-build-isolation -w /tmp/wheels \
       -r deploy/locks/tabrion.txt \
    && /opt/taskboard/bin/pip install --constraint deploy/constraints.txt \
       "$(ls /tmp/wheels/tabrion-*.whl)" "/src[server]" \
    && /opt/taskboard/bin/pip install --constraint deploy/constraints.txt ./examples/taskboard \
    && /opt/taskboard/bin/pip check \
    && /opt/taskboard/bin/python -I -c 'import json, importlib.metadata as m; d = json.loads(m.distribution("tabrion").read_text("direct_url.json") or "null"); assert d and "archive_info" in d and d["url"].startswith("file:///tmp/wheels/tabrion-"), d' \
    && /opt/taskboard/bin/taskboard --help > /dev/null

FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS runtime
LABEL org.opencontainers.image.title="Taskboard (Axentra demo)" \
      org.opencontainers.image.licenses="LicenseRef-Proprietary"
RUN groupadd --system --gid 10001 taskboard \
    && useradd --system --uid 10001 --gid taskboard --home-dir /var/lib/taskboard --create-home \
       --shell /usr/sbin/nologin taskboard \
    && install -d -o taskboard -g taskboard -m 0750 /var/lib/taskboard/var
COPY --from=build /opt/taskboard /opt/taskboard
ENV PATH=/opt/taskboard/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /var/lib/taskboard
USER 10001:10001
EXPOSE 8090
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8090/api/health', timeout=4).status == 200 else 1)"]
ENTRYPOINT ["taskboard"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8090"]
