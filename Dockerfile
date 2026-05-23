# Multi-stage build · 2026-05-23 · fix Coolify BuildKit/buildx helper issue.
# Pre-fix · single-stage simple · buildx component missing en helper container.
# Post-fix · multi-stage (builder + runtime) · mismo patrón que vurelo-backend HAv1
#           que SÍ deploya OK en mismo worker · evita el path roto del helper.

# ============ STAGE 1 · builder ============
FROM python:3.12-slim AS builder

WORKDIR /app

# Build tools solo en builder · NO terminan en runtime image
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# Install a directorio dedicado para copy a runtime
RUN pip install --no-cache-dir --user -r requirements.txt

# ============ STAGE 2 · runtime ============
FROM python:3.12-slim AS production

WORKDIR /app

# Copy installed packages desde builder · NO necesita gcc/libffi/libssl en runtime
COPY --from=builder /root/.local /root/.local

# Pip user installs van a /root/.local/bin · expose en PATH
ENV PATH=/root/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# App code
COPY *.py ./
COPY templates/ ./templates/
COPY static/ ./static/

# SQLite + auth secret persisten entre redeploys · Coolify monta /data como volume
ENV HOME=/data
RUN mkdir -p /data

EXPOSE 3000

# Bind 0.0.0.0 dentro del container · Traefik llega
ENV PORT=3000 \
    BIND_HOST=0.0.0.0

CMD ["sh", "-c", "python3 server.py --port $PORT --host $BIND_HOST --no-open"]
