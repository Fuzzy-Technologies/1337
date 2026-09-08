# syntax=docker/dockerfile:1

ARG PYTHON_IMAGE=python:3.11-slim-bookworm

FROM ${PYTHON_IMAGE} AS development

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_PROJECT_ENVIRONMENT=/opt/1337/.venv

RUN groupadd --gid 1337 workbench \
    && useradd --create-home --gid workbench --shell /usr/sbin/nologin --uid 1337 workbench

WORKDIR /workspace

RUN python -m pip install --no-cache-dir uv==0.11.33

COPY pyproject.toml uv.lock README.md LICENSE ./

RUN uv sync --locked --extra dev --no-install-project

COPY AGENTS.md CHANGELOG.md DEVELOPMENT_PROTOCOL.md SECURITY.md ./
COPY contracts ./contracts
COPY docs ./docs
COPY src ./src
COPY tests ./tests

RUN uv sync --locked --extra dev \
    && chown --recursive workbench:workbench /opt/1337 /workspace

USER workbench

ENTRYPOINT ["uv", "run", "--locked", "--extra", "dev"]
CMD ["1337", "--help"]
