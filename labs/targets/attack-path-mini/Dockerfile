ARG PYTHON_IMAGE=python:3.11-slim-bookworm

FROM ${PYTHON_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 1340 synthetic \
    && useradd --create-home --gid synthetic --shell /usr/sbin/nologin --uid 1340 synthetic

WORKDIR /opt/1337-lab

COPY billing.py client.py events.py http_common.py identity.py portal.py ./

USER synthetic

EXPOSE 8080

CMD ["python", "client.py", "serve"]
