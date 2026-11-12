# syntax=docker/dockerfile:1

# ---- Build stage: compile wheels so the runtime image carries no build tools ----
FROM python:3.12-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
 && pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt

# ---- Runtime stage ----
FROM python:3.12-slim AS runtime

# Nmap is NOT installed: the current scanner_core.py does its own HTTP-based
# checks (requests/BeautifulSoup) and never shells out to nmap. Add it back
# here (and to requirements) only if a future feature actually calls it -
# installing unused network-scanning tools in a public-facing container is an
# avoidable attack-surface and image-size cost.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /wheels /wheels
COPY requirements.txt .
RUN pip install --no-cache-dir --no-index --find-links=/wheels -r requirements.txt \
 && rm -rf /wheels

COPY app.py scanner_core.py security.py scan_store.py metrics.py ./
COPY templates/ templates/

# Non-root runtime user
RUN groupadd --system vulnscan && useradd --system --gid vulnscan --home /app vulnscan \
 && mkdir -p /app/reports \
 && chown -R vulnscan:vulnscan /app

USER vulnscan

# Configuration is injected via environment variables / Kubernetes Secrets -
# nothing is hardcoded here. See README "Environment variables" for the list.
ENV PORT=5000 \
    DATA_DIR=/app/reports \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/healthz" || exit 1

# eventlet worker matches the app's Socket.IO async_mode; one worker is
# required for in-process Socket.IO broadcast to stay consistent (see README
# "Scaling limitations" before trying to run >1 replica/worker).
CMD ["gunicorn", "--worker-class", "eventlet", "-w", "1", \
     "--bind", "0.0.0.0:5000", "--access-logfile", "-", "app:app"]
