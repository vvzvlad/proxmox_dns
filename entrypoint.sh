#!/bin/sh
# Postgres-style hybrid entrypoint: start as root, fix the state directory's ownership, then drop
# privileges to the unprivileged `app` user (uid 1000).
#
# Binding 53/udp and 80/tcp as uid 1000 needs no capability: docker sets
# net.ipv4.ip_unprivileged_port_start=0 inside a container, so there are no privileged ports in
# here. Nothing below grants anything for the sake of the ports, and docker-compose.yml adds no
# `cap_add` either.
set -e

if [ "$(id -u)" = "0" ]; then
    # The compose file mounts no volume, so this chown is for a future volume: docker seeds ownership
    # from the image only into an empty one. Guarded rather than left to `set -e`: on a read-only
    # mount or with userns-remap it fails, and exiting here would put the `.lc` DNS server into a
    # restart loop over a directory nothing writes to. chown's stderr is kept: it names the reason.
    if ! chown -R app:app /app/data; then
        echo "WARN: could not chown /app/data; continuing, this service writes nothing to it" >&2
    fi
    # exec, so python replaces this shell as PID 1 and receives `docker stop`'s SIGTERM. PID 1 has no
    # default signal dispositions, so src/app.py must install the handler; neither half works alone.
    exec gosu app "$@"
else
    # A compose `user:` override is in effect: exec straight through. No writability check, since
    # nothing in this image writes to /app/data.
    exec "$@"
fi
