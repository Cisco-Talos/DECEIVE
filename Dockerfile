# syntax=docker/dockerfile:1
FROM ghcr.io/astral-sh/uv:0.13.6 AS uv
FROM python:3.11-slim-bookworm AS build
COPY --from=uv /uv /uvx /bin/
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv uv sync --frozen --all-extras --no-dev --no-install-project
COPY README.md LICENSE ./
COPY deceive ./deceive
RUN --mount=type=cache,target=/root/.cache/uv uv sync --frozen --all-extras --no-dev --no-editable

FROM python:3.11-slim-bookworm AS runtime
RUN groupadd --gid 10001 deceive && useradd --uid 10001 --gid deceive --no-create-home deceive \
    && mkdir /data && chown deceive:deceive /data
COPY --from=build /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH" DECEIVE_DATA_DIR=/data PYTHONUNBUFFERED=1
USER 10001:10001
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8080/tcp 8022/tcp 8443/tcp 8443/udp
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s CMD ["deceive", "healthcheck"]
ENTRYPOINT ["deceive"]
CMD ["serve", "--profile", "demo-http"]
