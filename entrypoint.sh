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
    # proxmox_dns is STATELESS and its compose file mounts no volume: /app/data exists only inside
    # the image, where the Dockerfile already created it owned by app. So this chown repairs nothing
    # today — it is insurance for the day a volume does appear here, because docker seeds ownership
    # from the image only into an EMPTY volume and a pre-existing one keeps whatever it had.
    #
    # Guarded rather than left to `set -e`, and on a stateless service the guard is not a close call:
    # a read-only mount, a filesystem that carries no ownership, a daemon running with userns-remap
    # all fail this chown, and bare `set -e` would exit before `exec` on every one of them. With
    # `restart: always` that is an unbounded restart loop, and the thing looping is the authoritative
    # server for the whole `.lc` zone. A chown that cannot happen on a directory nothing writes to is
    # not worth taking name resolution off the network for, so it warns and carries on.
    #
    # chown's own stderr is deliberately NOT discarded: its message names the reason ("Read-only file
    # system", "Operation not permitted") and that line is the whole diagnosis for whoever reads the
    # log.
    if ! chown -R app:app /app/data; then
        echo "WARN: could not chown /app/data; continuing, this service writes nothing to it" >&2
    fi
    # exec, so python REPLACES this shell as PID 1: `docker stop` sends SIGTERM to PID 1 only, and a
    # shell that stayed there would swallow it and let the 10 s timeout run out into a SIGKILL.
    #
    # Necessary, and NOT sufficient. PID 1 receives no default signal dispositions from the kernel:
    # a signal PID 1 has installed no handler for is dropped, so a python that got here by `exec`
    # and then ignored SIGTERM would sit out the same 10 s and be killed just the same. The other
    # half lives in src/app.py, which installs the handler and waits on an Event instead of
    # sleeping. This line and that one only work as a pair; neither alone stops the container.
    exec gosu app "$@"
else
    # A compose `user:` override is in effect — respect it and exec straight through rather than
    # trying to become somebody else from an account that cannot. No writability check here, unlike
    # the stateful services this pattern comes from: nothing in this image writes to /app/data, so a
    # directory that uid cannot write is not a fault worth refusing to serve DNS over.
    exec "$@"
fi
