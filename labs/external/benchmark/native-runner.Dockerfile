ARG WORKBENCH_IMAGE
FROM ${WORKBENCH_IMAGE}

USER root
ARG SOURCE_REVISION
LABEL org.opencontainers.image.revision=${SOURCE_REVISION}
ENV BENCHMARK_SOURCE_REVISION=${SOURCE_REVISION} \
    PYTHONDONTWRITEBYTECODE=1

RUN /opt/1337/.venv/bin/python -m build --no-isolation --wheel --outdir /opt/benchmark-wheel \
    && python -m venv /opt/benchmark-runtime \
    && /opt/benchmark-runtime/bin/python -m pip install --no-index --no-deps /opt/benchmark-wheel/*.whl

COPY tests/functional/external_native_runner.py /opt/benchmark-runner.py
RUN /opt/benchmark-runtime/bin/python -I /opt/benchmark-runner.py --provision

USER 1337:1337
ENTRYPOINT ["/opt/benchmark-runtime/bin/python", "-I", "/opt/benchmark-runner.py"]
