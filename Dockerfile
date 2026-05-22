FROM python:3.12-slim

WORKDIR /app

# Dependencias del sistema (cryptography requiere libffi · build tools en slim)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY *.py ./
COPY templates/ ./templates/
COPY static/ ./static/

# SQLite + auth secret deben persistir entre redeploys
# Coolify monta /data como volume persistente
ENV HOME=/data
RUN mkdir -p /data

EXPOSE 3000

# Bind 0.0.0.0 dentro del container (no localhost) para que Traefik pueda llegar
ENV PORT=3000
ENV BIND_HOST=0.0.0.0
CMD ["sh", "-c", "python3 server.py --port $PORT --host $BIND_HOST --no-open"]
