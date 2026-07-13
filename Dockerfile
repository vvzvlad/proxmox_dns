FROM python:3.11-slim

WORKDIR /app

# curl is required by the compose healthcheck (not present in slim).
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Dependencies as a separate layer: change less often than code -> cached better
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Runtime state directory (proxdns is stateless, but keep the convention)
RUN mkdir -p data

# Code and static assets
COPY src/ src/
COPY templates/ templates/
COPY main.py .

# No EXPOSE: ports are published by docker-compose.

CMD ["python", "main.py"]
