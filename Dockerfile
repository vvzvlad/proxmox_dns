FROM python:3.11-slim

WORKDIR /app

# Unbuffered stdout/stderr: under docker the output is a pipe, so Python would block-buffer the
# startup lines and the configuration error that the CI smoke gate waits for in `docker logs`.
ENV PYTHONUNBUFFERED=1

# curl is required by the compose healthcheck (not present in slim).
# gosu drops privileges in /entrypoint.sh by exec, so python itself is PID 1 and receives SIGTERM;
# `su`/`sudo` fork and wait, leaving a shell as PID 1 that does not forward it. PID 1 also gets no
# default signal dispositions, so src/app.py installs its own handler (install_signal_handlers()).
# ci/smoke.py check (k) sends a real `docker stop` and fails the build if either half is lost.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl gosu \
    && rm -rf /var/lib/apt/lists/*

# The account the service runs as. uid 1000 is fixed because ci/smoke.py asserts PID 1 runs as 1000.
RUN useradd -m -u 1000 app

# Dependencies as a separate layer: change less often than code -> cached better
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Runtime state directory (proxmox_dns is stateless, but keep the convention). Docker copies this
# ownership only into an empty volume, which is why /entrypoint.sh chowns again at run time.
RUN mkdir -p data && chown app:app data

# Code and static assets
COPY src/ src/
COPY templates/ templates/
COPY main.py .
# --chmod: the executable bit does not survive every build context, and an exec-form ENTRYPOINT
# without it fails every container at start with `permission denied`.
COPY --chmod=0755 entrypoint.sh /entrypoint.sh

# No EXPOSE: ports are published by docker-compose.

# No `USER` line: /entrypoint.sh needs root to chown the state directory and drops to uid 1000 with
# gosu. Binding 53/udp and 80/tcp needs no privilege: docker sets
# net.ipv4.ip_unprivileged_port_start=0 inside the container.
#
# `docker exec` bypasses ENTRYPOINT and runs as root, so ci/smoke.py checks PID 1's uid, not its own.
ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "main.py"]
