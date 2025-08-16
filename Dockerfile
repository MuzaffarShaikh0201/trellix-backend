# ======================
# 1. Build stage
# ======================
FROM python:3.13.3-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir poetry

COPY pyproject.toml poetry.lock* ./

RUN poetry install --only main --no-root

COPY src ./src
COPY README.md ./README.md

RUN poetry build


# ======================
# 2. Runtime stage
# ======================
FROM python:3.13.3-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home devops
USER devops
WORKDIR /home/devops

ENV VIRTUALENV=/home/devops/venv
RUN python3 -m venv $VIRTUALENV
ENV PATH="$VIRTUALENV/bin:$PATH"

COPY --from=builder --chown=devops /app/dist/*.whl /app/
# Uncomment the below line if you want to run the application in local, also uncomment the .env from .dockerignore
# COPY .env .env

RUN pip install -U pip \
    && pip install --no-cache-dir /app/*.whl \
    && rm -rf /app/*.whl

ENTRYPOINT ["trellix-backend"]
