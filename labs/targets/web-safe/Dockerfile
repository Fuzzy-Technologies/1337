ARG PYTHON_IMAGE=python:3.11-slim-bookworm

FROM ${PYTHON_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 1338 synthetic \
    && useradd --create-home --gid synthetic --shell /usr/sbin/nologin --uid 1338 synthetic

WORKDIR /opt/1337-lab

COPY server.py ./

USER synthetic

EXPOSE 8080

HEALTHCHECK --interval=5s --timeout=3s --retries=3 --start-period=2s \
    CMD ["python", "-c", "from urllib.request import urlopen; urlopen('http://127.0.0.1:8080/health', timeout=1).read()"]

CMD ["python", "server.py"]
