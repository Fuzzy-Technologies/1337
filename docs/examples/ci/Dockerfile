# syntax=docker/dockerfile:1
# Supply an immutable python:3.11+-slim image digest from your approved registry.
ARG PYTHON_IMAGE
FROM ${PYTHON_IMAGE} AS builder
WORKDIR /source
COPY . .
RUN python -m pip install --no-cache-dir uv==0.11.33 \
    && uv sync --locked --extra dev --no-install-project \
    && uv build --no-build-isolation --python .venv/bin/python --wheel --out-dir /wheel

FROM ${PYTHON_IMAGE}
COPY --from=builder /wheel /wheel
RUN python -m pip install --no-cache-dir --no-deps /wheel/*.whl \
    && rm -rf /wheel
COPY docs/examples/ci/run_demo.py /opt/1337/run_demo.py
WORKDIR /tmp
ENTRYPOINT ["python", "-I", "/opt/1337/run_demo.py"]
CMD ["/artifacts"]
