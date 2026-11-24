FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY scripts/ ./scripts/
COPY studio/ ./studio/
COPY references/ ./references/
COPY assets/ ./assets/
COPY SKILL.md AGENTS.md README.md LICENSE ./

RUN useradd --create-home --shell /bin/bash monkeypaw \
    && mkdir -p /app/.monkey-paw /data \
    && chown -R monkeypaw:monkeypaw /app /data

USER monkeypaw

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8787

EXPOSE 8787

CMD ["python3", "-m", "studio", "--host", "0.0.0.0"]
