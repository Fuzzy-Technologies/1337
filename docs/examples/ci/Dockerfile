# syntax=docker/dockerfile:1
# Supply an immutable python:3.13+-slim image digest from your approved registry.
ARG PYTHON_IMAGE
FROM ${PYTHON_IMAGE} AS builder
WORKDIR /source
COPY . .
RUN python -m pip install --no-cache-dir uv==0.11.33 \
    && uv sync --locked --extra dev --no-install-project \
    && uv build --no-build-isolation --python .venv/bin/python --wheel --out-dir /wheel \
    && uv export --locked --no-dev --no-emit-project --format requirements.txt \
        --output-file /tmp/runtime-requirements.txt \
    && python -m pip download --only-binary=:all: --require-hashes \
        --dest /wheel --requirement /tmp/runtime-requirements.txt

FROM ${PYTHON_IMAGE}
COPY --from=builder /wheel /wheel
RUN python -m pip install --no-cache-dir --no-index --find-links=/wheel /wheel/1337-*.whl \
    && rm -rf /wheel
COPY docs/examples/ci/run_demo.py /opt/1337/run_demo.py
WORKDIR /tmp
ENTRYPOINT ["python", "-I", "/opt/1337/run_demo.py"]
CMD ["/artifacts"]
