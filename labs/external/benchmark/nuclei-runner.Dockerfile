# syntax=docker/dockerfile:1

ARG WORKBENCH_IMAGE
FROM ${WORKBENCH_IMAGE}

USER root
ARG SOURCE_REVISION
LABEL org.opencontainers.image.revision=${SOURCE_REVISION}

RUN --network=none /opt/1337/.venv/bin/python -m build --no-isolation --wheel --outdir /opt/benchmark-wheel \
    && python -m venv /opt/benchmark-runtime \
    && /opt/benchmark-runtime/bin/python -m pip install --no-index --no-deps /opt/benchmark-wheel/*.whl

ADD --checksum=sha256:234c12cc5288af071abdcd6f854245b6067345556e1235cf96b76725c1004357 \
    https://github.com/projectdiscovery/nuclei/releases/download/v3.4.10/nuclei_3.4.10_linux_amd64.zip \
    /opt/benchmark-download/nuclei_3.4.10_linux_amd64.zip
COPY labs/external/benchmark/templates/prometheus-exposition.yaml /opt/benchmark-input/prometheus-exposition.yaml
COPY labs/external/benchmark/nuclei-runner.Dockerfile /opt/benchmark-input/nuclei-runner.Dockerfile
COPY tests/functional/external_native_runner.py tests/functional/external_nuclei_runner.py \
    tests/functional/external_nuclei_provisioning.py tests/functional/external_nuclei_image.py \
    /opt/benchmark-support/tests/functional/

RUN --network=none /opt/benchmark-runtime/bin/python -I -B -c \
    "import sys; sys.path.insert(0, '/opt/benchmark-support'); from tests.functional.external_nuclei_image import Main; raise SystemExit(Main())" \
    --prepare --source-revision "${SOURCE_REVISION}"

USER 1337:1337
ENTRYPOINT ["/usr/bin/env", "-i", "PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8", "/opt/benchmark-runtime/bin/python", "-I", "-B", "-c", "import sys; sys.path.insert(0, '/opt/benchmark-support'); from tests.functional.external_nuclei_image import Main; raise SystemExit(Main())"]
CMD ["--prerequisites"]
