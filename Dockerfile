FROM python:3.11-slim

WORKDIR /app

# Unbuffered stdout/stderr. Without it Python block-buffers when its output is a pipe — which is
# exactly what it is under docker — so the startup lines and the configuration error would sit in a
# 8 KB buffer instead of reaching `docker logs`. That matters twice over here: those lines are what
# the CI smoke gate waits for, and on a box they are the only thing that says why a container that
# exited immediately did so.
ENV PYTHONUNBUFFERED=1

# curl is required by the compose healthcheck (not present in slim).
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Dependencies as a separate layer: change less often than code -> cached better
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Runtime state directory (proxmox_dns is stateless, but keep the convention)
RUN mkdir -p data

# Code and static assets
COPY src/ src/
COPY templates/ templates/
COPY main.py .

# No EXPOSE: ports are published by docker-compose.

CMD ["python", "main.py"]
