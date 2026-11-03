# syntax=docker/dockerfile:1
# Axentra API container image.
#
#   docker build -t axentra:local .
#   docker build --build-arg EXTRAS=server,oidc,s3,otel -t axentra:full .
#
# Dependencies are pinned by deploy/constraints.txt (see the header there to regenerate).
# The image runs as an unprivileged user (uid/gid 10001) and contains no compiler or build tools.

# The base is pinned by digest in each FROM line (Dependabot's docker ecosystem keeps both current).

# --- build: install Axentra and its pinned dependencies into a self-contained venv -------------
FROM python:3.13-slim@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb AS build
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1
RUN python -m venv /opt/axentra
WORKDIR /src
COPY deploy/constraints.txt deploy/constraints.txt
COPY pyproject.toml README.md LICENSE CHANGELOG.md NOTICE.md ./
COPY src ./src
ARG EXTRAS=server
RUN /opt/axentra/bin/pip install --constraint deploy/constraints.txt "/src[${EXTRAS}]" \
    && /opt/axentra/bin/axentra --version

# --- runtime ------------------------------------------------------------------------------------
FROM python:3.13-slim@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb AS runtime
LABEL org.opencontainers.image.title="Axentra" \
      org.opencontainers.image.description="Modular SaaS backend foundation (HTTP API)" \
      org.opencontainers.image.source="https://github.com/peterkarlhuber/axentra" \
      org.opencontainers.image.licenses="MIT"
RUN groupadd --system --gid 10001 axentra \
    && useradd --system --uid 10001 --gid axentra --home-dir /var/lib/axentra --create-home \
       --shell /usr/sbin/nologin axentra \
    && install -d -o axentra -g axentra -m 0750 /var/lib/axentra/var
COPY --from=build /opt/axentra /opt/axentra
ENV PATH=/opt/axentra/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
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
