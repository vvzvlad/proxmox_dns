FROM python:3.11-slim

WORKDIR /app

# Unbuffered stdout/stderr. Without it Python block-buffers when its output is a pipe — which is
# exactly what it is under docker — so the startup lines and the configuration error would sit in a
# 8 KB buffer instead of reaching `docker logs`. That matters twice over here: those lines are what
# the CI smoke gate waits for, and on a box they are the only thing that says why a container that
# exited immediately did so.
ENV PYTHONUNBUFFERED=1

# curl is required by the compose healthcheck (not present in slim).
# gosu is what /entrypoint.sh drops privileges with. `su` and `sudo` are not interchangeable with it
# here: both fork and wait, which leaves PID 1 a shell that does not forward SIGTERM — so `docker
# stop` would sit out its full 10 s timeout and then SIGKILL the DNS server, on every single
# redeploy of the service the whole `.lc` zone resolves through. gosu execs, so the python process
# itself is PID 1 and the signal is DELIVERED to it.
#
# Delivery is only half of a working `docker stop`, and the half that is usually missed is the
# other one: PID 1 gets NO default signal dispositions from the kernel, so a SIGTERM that PID 1 has
# installed no handler for is DROPPED. Being PID 1 is therefore not enough on its own — it is what
# makes the signal arrive, not what makes it do anything. src/app.py installs the handler
# (install_signal_handlers()), and its main loop waits on an Event rather than sleeping, so the two
# together are what make the container exit 0 in well under a second. ci/smoke.py check (k) sends a
# real `docker stop` and fails the build if either half is lost.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl gosu \
    && rm -rf /var/lib/apt/lists/*

# The account the service actually runs as. uid 1000 is spelled out rather than left to useradd's
# next-free pick because two other places are pinned to that number: the chown below, and the
# assertion in ci/smoke.py that PID 1 is 1000 and not root. A fixed uid also keeps ownership stable
# across image rebuilds, which is what makes the number worth anything the day a volume appears.
RUN useradd -m -u 1000 app

# Dependencies as a separate layer: change less often than code -> cached better
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Runtime state directory (proxmox_dns is stateless, but keep the convention). Owned by app so that
# a named volume first initialised from this image inherits that ownership — docker copies it only
# into an EMPTY volume, which is why /entrypoint.sh chowns again at run time.
RUN mkdir -p data && chown app:app data

# Code and static assets
COPY src/ src/
COPY templates/ templates/
COPY main.py .
# --chmod is not decoration: ENTRYPOINT in exec form does not go through a shell, so a script that
# arrives without its executable bit does not fail the build — it fails every container at start
# with `permission denied`. The bit does not survive every build context (a checkout on a filesystem
# with no POSIX permissions drops it), so it is set here rather than hoped for.
COPY --chmod=0755 entrypoint.sh /entrypoint.sh

# No EXPOSE: ports are published by docker-compose.

# There is deliberately NO `USER` line. root is what /entrypoint.sh needs to chown the state
# directory, and it drops to uid 1000 itself with gosu; a static USER here would take that root away
# before the entrypoint could use it. Note that binding 53/udp and 80/tcp needs no privilege at all:
# docker sets net.ipv4.ip_unprivileged_port_start=0 inside the container, so there are no privileged
# ports in here — see the note in docker-compose.yml.
#
# `docker exec` does NOT go through ENTRYPOINT, which is why ci/smoke.py's in-container probes still
# arrive as root — and why the one thing they must never ask is their OWN uid. They read PID 1's
# instead, which is the only process here that came through this line.
ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "main.py"]
