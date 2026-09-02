"""Smoke gate for the proxmox_dns image, run on the CI runner against an already-built image.

It sits BETWEEN `docker build` and `docker push`, which is the only place it is worth anything:
nobody presses a button between the push and the rollout — the deployed stack carries
`io.portainer.update.enable`, so an updater polls `:latest` and redeploys whatever lands on it. This
gate is the last point at which a broken image can still be stopped.

What it is guarding is unusually load-bearing for a service this small: proxmox_dns answers DNS for
the whole internal `.lc` zone. An image that starts but does not serve does not degrade the network,
it removes name resolution from it.

THE SPLIT
---------
The OUTER half is this file: a plain `python3 ci/smoke.py` on the runner, driving `docker`. It
answers the questions that are about the container as an OBJECT — what `docker inspect` says its CMD
and WORKDIR are, what the real command writes to its log, whether a run with no configuration
refuses to start, whether the container is still alive when everything else is done. None of those
can be answered from a process already running inside it.

The two INNER halves are PROBES: programs that live here as string constants and are fed to
`docker exec -i <name> python -u -`. The IMAGE probe answers everything about the FILES and the
dependencies inside the image. The SERVICE probe answers WHO the running process is and whether it
is really SERVING — over HTTP and, more importantly, over DNS.

They run inside for two reasons. The obvious one is that those objects only exist in there. The
other shapes this whole file: **this job and the docker daemon are not in the same network
namespace.** Gitea's act_runner executes the job inside its own job container while the `docker` CLI
it provides drives a daemon outside it.

NO PORT IS PUBLISHED by anything here, and for this service that is a real trap rather than a
detail: it does listen — 53/udp and 80/tcp — so publishing looks like the obvious way to check it.
It would check nothing. A published port lands in the HOST daemon's network namespace, and this
job's 127.0.0.1 is a different loopback entirely, so the gate would be talking to its own empty port.
Everything internal therefore goes through `docker exec`, which puts the probe in the container's own
namespace — where 127.0.0.1 means what the compose healthcheck means by it.

Two more properties of `docker exec` are worth stating because checks below depend on them, and both
cut the same way. It does NOT go through ENTRYPOINT, and it runs as the image's `Config.User` —
which the Dockerfile deliberately leaves unset, so every probe here arrives as ROOT while the
service itself does not. The image declares `/entrypoint.sh`, which starts as root, chowns the state
directory and `exec`s gosu to drop to uid 1000. A probe that asked for its OWN uid would therefore
answer 0 on a perfectly good image, and 0 just the same on one that never drops privileges at all.
So the non-root check interrogates PID 1 — the only process in the container that came through the
entrypoint — and the contract check pins the ENTRYPOINT to an exact value rather than reading the
privilege drop off the image's declarations, which cannot show whether it still happens.

Nothing here grants a capability to bind 53/udp, and nothing needs to: docker sets
net.ipv4.ip_unprivileged_port_start=0 inside a container, so uid 1000 binds 53 and 80 with an empty
capability set. That is why docker-compose.yml carries no `cap_add` and why the containers below are
started without one — the gate runs the image the way production does.

WHY A CONTAINER WITH NO PROXMOX IS THE CORRECT TEST BED
-------------------------------------------------------
The serving container is started with credentials that point at 127.0.0.1, where no PVE is
listening. That is deliberate, and it is the single most important thing to understand before
editing check (d).

proxmoxer authenticates EAGERLY: `ProxmoxAPI(...)` builds a `ProxmoxHTTPAuth` whose `__init__` posts
to `/access/ticket`. So building the client is a network call, and an unreachable PVE raises out of
the CONSTRUCTOR. src/app.py used to call `build_client()` on the first line of `run()`, which meant
an unreachable PVE killed the process BEFORE the DNS and HTTP servers ever bound — and with
`restart: always` that is a crash loop in which the zone resolves nowhere at all.
`ensure_client()` is the fix: the client is built lazily, the servers start regardless, and the
updater retries.

So the gate boots the image into exactly that state on purpose. It is not a compromise made because
CI has no Proxmox — it is the regression under test. If the eager call ever comes back, the three
startup markers below stop appearing and this gate goes red before the image can reach the registry.

An empty zone is also what makes the DNS check exact rather than approximate: with no VMs known,
src/dns_server.py answers NXDOMAIN, so there is one right answer to compare against instead of
whatever a live cluster happens to hold.

THE CHECKS
----------
Each one is written against a way this image has a realistic chance of shipping broken:

* (a) the image's declared contract: CMD, WORKDIR, and the ENTRYPOINT that drops privileges. Outer
      half.
* (b) `curl` is present AND runs. Not cosmetic and not a style preference: the compose healthcheck
      is `["CMD", "curl", "-f", "http://localhost:80"]`, and the Portainer updater waits 120 s for
      `healthy` before rolling the image back. A base-image bump that drops curl does not fail
      loudly — every subsequent update silently rolls back while the image itself looks fine.
      Image probe.
* (c) the configuration guard really refuses: started with NO environment, the image names ALL
      THREE required variables and exits non-zero. Outer half.
* (d) the real command starts and reports all three startup markers with PVE unreachable — the
      regression described above. Outer half.
* (e) the HTTP status server answers: /health, /json, / and a 404 for anything else. Service probe.
* (f) the DNS server answers a real UDP query on 127.0.0.1:53, for both an A question and a PTR
      question — PTR takes a separate branch through src/dns_server.py and would not be covered by
      the A query. Service probe.
* (g) .dockerignore did its job: no tests/, .env, .venv or .gitea/ in the image. Image probe.
* (h) the runtime dependencies import: dns, proxmoxer, pydantic_settings, requests. Image probe.
* (i) the container is still alive once everything else has had its turn at it, and the log it has
      at the very end, after (k) has stopped it, carries no traceback. Outer half.
* (j) PID 1 — the process the ENTRYPOINT actually started — serves as uid 1000 and not as root. This
      is the artefact, not the intention: a Dockerfile can carry every non-root instruction there is
      and still serve as root the moment /entrypoint.sh stops `exec`ing gosu, and (a) would not see
      it — an image keeps declaring its ENTRYPOINT whatever the script inside it does. Service
      probe, because it is the only one running where PID 1 can be read.
* (k) `docker stop` really stops it: SIGTERM reaches PID 1, something ACTS on it, and the container
      exits 0 instead of sitting out the grace period until the kernel kills it. Two things have to
      hold for that, and only one of them is visible anywhere else in this file. /entrypoint.sh must
      `exec`, so python is PID 1 and the signal is delivered at all — (j) catches only the crudest
      loss of that, since under `su` PID 1 would run as uid 0, while a `sh -c "python main.py"`
      wrapper keeps the uid and drops the signal all the same. AND src/app.py must install a
      handler, because PID 1 gets NO default signal dispositions from the kernel: an unhandled
      SIGTERM at PID 1 is dropped rather than applied, so a process that is PID 1 and does nothing
      about it passes every other check in this file and still has to be SIGKILLed. Every redeploy
      would then take the `.lc` zone down for the whole grace period instead of for the second it
      takes to swap the container. Runs LAST of everything that touches the container, because it
      ENDS it. Outer half.

Two properties matter and are easy to lose, so they are stated where they can be checked:

* Failures leave through SystemExit, never `assert` — on all three sides of the split. Asserts vanish
  under PYTHONOPTIMIZE=1, which would silently turn this gate permanently green.
* Every check runs before the run is judged, so one run shows the full extent of the breakage
  instead of only the first broken thing. A check that CANNOT run reports itself as FAILED; it is
  never quietly skipped, which is the classic way a gate keeps reporting success while proving less
  and less. Each probe's own report lines are parsed back into this gate's report, so a failure
  inside the container is one row in the same list as a failure outside it.

Nothing here holds a credential, and nothing it starts reaches a service outside the runner: the
only address the container is given is 127.0.0.1, and the password is a literal that authenticates
nothing. That is what lets this same gate run on a pull request.
"""

import json
import os
import subprocess
import time

# The tag to test. Required rather than defaulted: a default would let a mistyped `env:` block in a
# workflow silently gate some other image that happens to be on the daemon.
IMAGE_ENV = "SMOKE_IMAGE"
# Base name for every container this gate starts. The workflows put the run id in it, because the
# runner has ONE docker daemon shared by every repository in the fleet and two concurrent runs must
# not collide on a name — remove_container() below would otherwise delete another run's live
# container out from under it. Required for a second reason too: the workflow's `if: always()`
# cleanup step builds the same names from the same variable, so a default here would leave this
# script naming its containers one way while the cleanup went looking for another, found nothing,
# and swallowed the miss in its `|| true`.
NAME_ENV = "SMOKE_NAME"

GUARD_SUFFIX = "-guard"
SERVE_SUFFIX = "-serve"
# Kept in step with the cleanup step in both workflows.
ALL_SUFFIXES = (GUARD_SUFFIX, SERVE_SUFFIX)

# --- The image's declared contract -------------------------------------------------------------
APP_DIR = "/app"
EXPECTED_CMD = ["python", "main.py"]
# Pinned to an exact value rather than merely asserted to exist. This is the only script that stands
# between the image and serving as root, and every other check in this gate reaches the container
# through `docker exec`, which walks straight past it — so an image that lost the ENTRYPOINT would
# answer all of them exactly as it does now while quietly going back to running python as uid 0.
EXPECTED_ENTRYPOINT = ["/entrypoint.sh"]

# --- The three startup markers ------------------------------------------------------------------
# All three are logged at CRITICAL by src/app.py, src/dns_server.py and src/http_server.py, so they
# survive any LOG_LEVEL. The DNS and HTTP ones are printed from their own threads, so the ORDER
# between them is not fixed — which is why the wait below is for all three rather than for a last
# one, and why nothing here reads them positionally.
STARTUP_MARKER = "ProxDNS server started"
DNS_MARKER = "[DNS] Server run on port 53/udp on 0.0.0.0..."
HTTP_MARKER = "[HTTP] Server started on port 80..."
STARTUP_MARKERS = (STARTUP_MARKER, DNS_MARKER, HTTP_MARKER)

# --- What the configuration guard must say ------------------------------------------------------
# src/config_errors.py prints this block to stderr and raises SystemExit(1) when a required variable
# is missing. All three names are required in the output: a guard that named only the first would
# send an operator round the loop once per variable.
GUARD_HEADER = "Configuration error in environment / .env:"
GUARD_MISSING_LINE = "Missing required variable(s):"
REQUIRED_VARIABLES = ("PROXMOX_HOST", "PROXMOX_USER", "PROXMOX_PASSWORD")

# --- The environment the serving container gets -------------------------------------------------
# 127.0.0.1 is the point: nothing listens on the PVE API port inside the container, so the client
# cannot be built and the gate observes the exact state the ensure_client() fix exists for. The
# password authenticates nothing anywhere; there is no host in this list that resolves off the
# runner.
SERVE_ENV = [
    "PROXMOX_HOST=127.0.0.1",
    "PROXMOX_USER=smoke@pve",
    "PROXMOX_PASSWORD=not-a-real-password",
]

TRACEBACK_MARKER = "Traceback (most recent call last)"

# --- Probe markers and their exact target counts ------------------------------------------------
# Each probe prints its marker with a count on its LAST line. The count is compared exactly, not
# searched for as a substring: a probe that stopped emitting rows would otherwise finish, exit 0,
# and take its own missing verdicts with it — the one failure mode nothing else here can see,
# because every row it DID print says ok.
IMAGE_PROBE_MARKER = "proxmox_dns image probe ok"
SERVICE_PROBE_MARKER = "proxmox_dns service probe ok"
EXPECTED_IMAGE_PROBE_TARGETS = 11
# 1 identity + 2 /health + 2 /json + 2 / + 1 404 + 2 per DNS question, A and PTR.
EXPECTED_SERVICE_PROBE_TARGETS = 12

IMAGE_PROBE_ROW_PREFIX = "[in-image] "
SERVICE_PROBE_ROW_PREFIX = "[in-container] "

# Total verdicts a healthy run ends with, checked against the real count before the summary is
# printed. Outer half: 3 contract + 6 config guard + 1 serving start + 3 startup markers + 1 alive
# + 2 SIGTERM shutdown + 1 clean log = 17. Each probe contributes its own targets plus the two
# consistency rows run_probe appends (its exit status, and that it ran to its end).
EXPECTED_OUTER_TARGETS = 17
EXPECTED_TOTAL_TARGETS = (
    EXPECTED_OUTER_TARGETS
    + EXPECTED_IMAGE_PROBE_TARGETS + 2
    + EXPECTED_SERVICE_PROBE_TARGETS + 2)

# --- Bounds -------------------------------------------------------------------------------------
# Every docker call is bounded, so a hung daemon surfaces as a named failure rather than as a step
# killed by its own timeout with nothing said about which call stopped.
INSPECT_TIMEOUT = 30
REMOVE_TIMEOUT = 30
GUARD_TIMEOUT = 60
START_TIMEOUT = 60
LOGS_TIMEOUT = 30
IMAGE_PROBE_TIMEOUT = 120
SERVICE_PROBE_TIMEOUT = 120
# What `docker stop` gives the process before the kernel takes over, and it has to be generous for
# check (k) to mean anything: a bound short enough to kill a process that WAS shutting down would
# report a working image as one that never got the signal. A correct image needs a fraction of this
# — the main loop returns as soon as the handler sets its Event and the interpreter exits.
#
# DELIBERATELY NOT the 45 s docker-compose.yml asks for. That value buys the SLOW case: a stop that
# lands while the startup fetch is out at an unreachable PVE, which PEP 475 makes the process finish
# before it notices anything. This gate stops a container that is long past startup and sitting in
# its reporting loop, so the slow case is not the one under test here — and copying 45 s in would
# only make a genuinely wedged image take more than twice as long to be reported as wedged.
SIGTERM_GRACE = 20
# Must exceed SIGTERM_GRACE, or the docker CLIENT would be killed on the runner while the daemon
# was still waiting out the grace period — and the container would then be judged by an inspect
# that ran mid shutdown.
STOP_TIMEOUT = 60

# Wall-clock budget for all three startup markers to appear. Generous against a cold, loaded runner:
# the process has to import pydantic, dnspython and proxmoxer, fail one connection attempt to
# 127.0.0.1 (refused instantly, not timed out) and bind two sockets.
BOOT_BUDGET = 60
BOOT_PAUSE = 0.5

EXCERPT_CHARS = 4000


# ================================================================================================
# The IMAGE probe: files and dependencies inside the image.
# ================================================================================================
# Runs via `docker exec` in the SERVING container rather than in an idle one of its own. That is a
# deliberate simplification this image earns: its real command survives an unreachable PVE (see the
# module docstring), so the container running the actual service is available to be asked about its
# own files — which is a slightly stronger claim than asking a container started with a sleep.
IMAGE_PROBE = r'''
import os
import subprocess
import sys

PROBE_MARKER = "proxmox_dns image probe ok"

APP_DIR = "/app"
# Anchors. The four absence checks below are only meaningful if we are looking at a populated
# image: in an empty /app every one of them would pass while proving nothing at all. These two say
# the code really is where the absences are being asserted.
PRESENT = [
    ("/app/main.py", "the entry point the image's CMD runs"),
    ("/app/src/app.py", "the application package"),
]
# What .dockerignore is supposed to have kept out. tests/ and .gitea/ are build-time only; .venv is
# a host-built tree that would shadow the interpreter's own packages; .env is the one that matters
# most, because a leaked one would carry real Proxmox credentials into a published image AND would
# quietly satisfy the configuration guard that check (c) relies on being able to fail.
# The workflow directory is named for the forge this repo actually lives on: a check written against
# `.github` would pass on every build without ever looking at a path this repository contains, which
# is the shape of a check that has quietly stopped proving anything.
ABSENT = [
    ("/app/tests", "the test tree"),
    ("/app/.env", "a real credentials file"),
    ("/app/.venv", "a host-built virtualenv"),
    ("/app/.gitea", "the CI workflow directory"),
]
# The runtime dependencies, by the name the code imports them under.
IMPORTS = ["dns", "proxmoxer", "pydantic_settings", "requests"]


def describe(error):
    return "{}: {}".format(type(error).__name__, error)


def check_curl():
    """curl has to RUN, not merely exist.

    The compose healthcheck shells out to it, and the Portainer updater rolls the image back when a
    container does not reach `healthy` within 120 s. A curl that is present but cannot execute — a
    missing shared library after a base-image bump — produces exactly that silent rollback, with
    nothing anywhere reporting a fault in the image.
    """
    try:
        completed = subprocess.run(
            ["curl", "--version"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    except FileNotFoundError:
        return ("curl is installed and runs", (
            "there is no curl on PATH. The compose healthcheck is `curl -f http://localhost:80`, so "
            "every container from this image would stay unhealthy and the updater would roll each "
            "deployment back"))
    except Exception as error:
        return ("curl is installed and runs", describe(error))
    output = (completed.stdout or b"").decode("utf-8", "replace").strip()
    if completed.returncode != 0:
        return ("curl is installed and runs", (
            "`curl --version` exited {}. It is on PATH but cannot execute, which the compose "
            "healthcheck cannot tell from it being absent. Output:\n{}".format(
                completed.returncode, output)))
    if not output.startswith("curl "):
        return ("curl is installed and runs", (
            "`curl --version` exited 0 but printed {!r}, which is not a curl banner".format(
                output[:200])))
    return ("curl is installed and runs ({})".format(output.splitlines()[0]), None)


def check_present(path, what):
    target = "the image ships {} ({})".format(path, what)
    if os.path.exists(path):
        return (target, None)
    return (target, (
        "it is not in the image. Either the Dockerfile stopped copying it or the working directory "
        "moved, and in both cases the checks that assert other paths are ABSENT are now passing "
        "trivially"))


def check_absent(path, what):
    target = "the image is free of {} ({})".format(path, what)
    if not os.path.exists(path):
        return (target, None)
    return (target, (
        "it IS in the image, so .dockerignore no longer excludes it. Check the .dockerignore entry "
        "for this path"))


def check_import(module):
    target = "the image can import {}".format(module)
    try:
        __import__(module)
    except Exception as error:
        return (target, (
            "importing it raised {}. The application imports this at startup, so the container "
            "would die before serving anything".format(describe(error))))
    return (target, None)


def main():
    rows = [check_curl()]
    for path, what in PRESENT:
        rows.append(check_present(path, what))
    for path, what in ABSENT:
        rows.append(check_absent(path, what))
    for module in IMPORTS:
        rows.append(check_import(module))

    failures = []
    for target, reason in rows:
        if reason is None:
            print("ok   {}".format(target))
        else:
            print("FAIL {} -> {}".format(target, reason))
            failures.append(target)

    print("{}: {}/{} targets".format(PROBE_MARKER, len(rows) - len(failures), len(rows)))
    if failures:
        # SystemExit, never assert: an assert would vanish under PYTHONOPTIMIZE and take the whole
        # probe's ability to fail with it.
        raise SystemExit(1)


if __name__ == "__main__":
    main()
'''


# ================================================================================================
# The SERVICE probe: is the running process actually serving, over HTTP and over DNS?
# ================================================================================================
# Runs inside the serving container, which is the only place 127.0.0.1 means the application's own
# loopback — the same thing the compose healthcheck means by localhost.
SERVICE_PROBE = r'''
import json
import urllib.error
import urllib.request

import dns.exception
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

PROBE_MARKER = "proxmox_dns service probe ok"

BASE_URL = "http://127.0.0.1:80"
HTTP_TIMEOUT = 10

DNS_ADDRESS = "127.0.0.1"
DNS_PORT = 53
DNS_TIMEOUT = 10

# The uid the Dockerfile creates and /entrypoint.sh drops to with gosu. Checked against PID 1 and
# NOT against this probe's own uid: `docker exec` does not go through ENTRYPOINT and runs as the
# image's Config.User, which the Dockerfile deliberately leaves unset — so os.getuid() here is 0 on
# a perfectly good image and would be 0 just the same on one that never drops privileges at all.
# PID 1 is the only process in this container that came through the entrypoint.
APP_UID = 1000
# A name in the served zone that no VM can be called, and a PTR for a TEST-NET-1 address. With an
# unreachable PVE the domain list is empty, so src/dns_server.py must answer NXDOMAIN to both.
UNKNOWN_NAME = "nothing-here-smoke.lc"
UNKNOWN_PTR = "1.2.0.192.in-addr.arpa"


def describe(error):
    return "{}: {}".format(type(error).__name__, error)


def fetch(path):
    """GET a path, returning (status, body, error).

    A 404 arrives as an HTTPError rather than a response, and that is a legitimate answer here — one
    of the checks below is looking for exactly one — so it is unwrapped into the same shape as a 200
    instead of being treated as a failure.
    """
    try:
        with urllib.request.urlopen(BASE_URL + path, timeout=HTTP_TIMEOUT) as response:
            return response.getcode(), response.read().decode("utf-8", "replace"), None
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace"), None
    except Exception as error:
        return None, "", describe(error)


def pid1_uid():
    """The REAL uid of PID 1, read out of procfs.

    The `Uid:` line in /proc/<pid>/status is tab-separated as real, effective, saved, fs. The FIRST
    column is the one taken: an effective uid of 1000 sitting on a real uid of 0 is a process that
    can climb straight back, and reading the second column would call that a pass.

    procfs and not `ps`: python:3.11-slim ships no procps, so a `ps` here would fail on the image
    being tested rather than on anything it is testing.
    """
    with open("/proc/1/status") as handle:
        for line in handle:
            if line.startswith("Uid:"):
                return int(line.split()[1])
    return None


def check_process_identity():
    """(j) Who is actually serving — the running process, not the image's declarations.

    This interrogates the artefact rather than the intention, and that is the entire point: a
    Dockerfile can carry every non-root instruction there is while /entrypoint.sh has quietly
    stopped `exec`ing gosu, and no other check in this gate would see the difference — they all
    arrive through `docker exec`, which never goes through the entrypoint at all.

    Runs FIRST, before the HTTP and DNS checks, so that the identity of the process answering them
    is established before anything is asked of it.
    """
    target = "PID 1 serves as uid {} rather than as root".format(APP_UID)
    try:
        uid = pid1_uid()
    except Exception as error:
        return [(target, "/proc/1/status could not be read: {}".format(describe(error)))]
    if uid is None:
        return [(target, (
            "/proc/1/status carried no Uid: line, so the serving process cannot be identified and "
            "this claim cannot be made about it"))]
    return [(target, None if uid == APP_UID else (
        "it runs as uid {}. {}".format(uid, (
            "That is root: the privilege drop did not happen. Either /entrypoint.sh stopped "
            "`exec`ing gosu, or the ENTRYPOINT is off the image and the CMD ran on its own"
        ) if uid == 0 else (
            "That is neither root nor the `app` account the image creates, so the ownership the "
            "Dockerfile and the entrypoint put on /app/data belongs to somebody else"))))]


def check_health():
    rows = []
    status, body, error = fetch("/health")
    target = "GET /health answers 200"
    if error is not None:
        rows.append((target, (
            "the request failed with {}. This is the endpoint the compose healthcheck polls, so a "
            "container in this state never reaches `healthy`".format(error))))
        rows.append(("GET /health returns the body `ok`", "not attempted: the request failed"))
        return rows
    rows.append((target, None if status == 200 else "it answered {}".format(status)))
    rows.append((
        "GET /health returns the body `ok`",
        None if body.strip() == "ok" else "the body was {!r}".format(body[:200])))
    return rows


def check_json():
    rows = []
    status, body, error = fetch("/json")
    target = "GET /json answers 200"
    if error is not None:
        rows.append((target, "the request failed with {}".format(error)))
        rows.append(("GET /json returns a JSON list", "not attempted: the request failed"))
        return rows
    rows.append((target, None if status == 200 else "it answered {}".format(status)))
    try:
        document = json.loads(body)
    except ValueError as error:
        rows.append(("GET /json returns a JSON list", (
            "the body does not parse as JSON ({}): {!r}".format(describe(error), body[:200]))))
        return rows
    rows.append((
        "GET /json returns a JSON list",
        None if isinstance(document, list) else (
            "it parsed, but as {} rather than the list of domains the endpoint documents".format(
                type(document).__name__))))
    return rows


def check_index():
    rows = []
    status, body, error = fetch("/")
    target = "GET / answers 200"
    if error is not None:
        rows.append((target, "the request failed with {}".format(error)))
        rows.append(("GET / returns an HTML table", "not attempted: the request failed"))
        return rows
    rows.append((target, None if status == 200 else "it answered {}".format(status)))
    rows.append((
        "GET / returns an HTML table",
        None if "<table" in body else (
            "the body carries no <table element: {!r}".format(body[:200]))))
    return rows


def check_unknown_path():
    status, _body, error = fetch("/definitely-not-a-route")
    target = "GET an unrouted path answers 404"
    if error is not None:
        return [(target, "the request failed with {}".format(error))]
    return [(target, None if status == 404 else "it answered {}".format(status))]


def ask_dns(label, question_name, rdtype):
    """Send one REAL UDP query to the server's own socket and judge the reply.

    Two verdicts per question, and both are positive statements about the reply: that it says
    NXDOMAIN, and that its id is the id we sent. The id check is what separates "the server answered
    us" from "something answered"; dnspython also matches it internally, so a mismatch surfaces as a
    failure to receive rather than as a wrong answer — either way this row is the one that reports
    it.

    PTR is asked as well as A because src/dns_server.py handles it in a separate branch, with its own
    reverse-name parsing. An A query alone would leave that branch uncovered.
    """
    rcode_target = "a UDP {} query to {}:{} is answered NXDOMAIN".format(
        label, DNS_ADDRESS, DNS_PORT)
    id_target = "the UDP {} reply carries the id of the query".format(label)
    query = dns.message.make_query(question_name, rdtype)
    try:
        response = dns.query.udp(query, DNS_ADDRESS, port=DNS_PORT, timeout=DNS_TIMEOUT)
    except dns.exception.Timeout:
        reason = (
            "nothing answered within {} s. The zone this server is authoritative for resolves "
            "nowhere in this state".format(DNS_TIMEOUT))
        return [(rcode_target, reason), (id_target, "not attempted: no reply arrived")]
    except Exception as error:
        return [(rcode_target, describe(error)),
                (id_target, "not attempted: the query did not complete")]

    rows = []
    rows.append((
        rcode_target,
        None if response.rcode() == dns.rcode.NXDOMAIN else (
            "it answered {}. With no VMs known the domain list is empty, so every name is supposed "
            "to come back NXDOMAIN".format(dns.rcode.to_text(response.rcode())))))
    rows.append((
        id_target,
        None if response.id == query.id else (
            "the reply's id is {} and the query's was {}".format(response.id, query.id))))
    return rows


def main():
    rows = []
    rows.extend(check_process_identity())
    rows.extend(check_health())
    rows.extend(check_json())
    rows.extend(check_index())
    rows.extend(check_unknown_path())
    rows.extend(ask_dns("A", UNKNOWN_NAME, dns.rdatatype.A))
    rows.extend(ask_dns("PTR", UNKNOWN_PTR, dns.rdatatype.PTR))

    failures = []
    for target, reason in rows:
        if reason is None:
            print("ok   {}".format(target))
        else:
            print("FAIL {} -> {}".format(target, reason))
            failures.append(target)

    print("{}: {}/{} targets".format(PROBE_MARKER, len(rows) - len(failures), len(rows)))
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
'''


# ================================================================================================
# The outer half.
# ================================================================================================
def excerpt(text):
    """Bound what reaches the log, and say so when something was cut."""
    if text is None:
        return ""
    if len(text) <= EXCERPT_CHARS:
        return text
    return text[:EXCERPT_CHARS] + "\n[... truncated at {} characters]".format(EXCERPT_CHARS)


def docker(args, timeout, stdin_text=None):
    """Run a docker command.

    Returns (status, output) with stderr folded into stdout, because everything here is read by a
    human out of a CI log where the interleaving is the useful part. A status of None means the
    command produced no exit code at all — it timed out, or docker is not there — and `output` then
    explains which. Callers must keep that case apart from a non-zero exit: they mean different
    things and only one of them is a verdict about the image.
    """
    argv = ["docker"] + args
    try:
        completed = subprocess.run(
            argv,
            input=stdin_text,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            text=True)
    except FileNotFoundError:
        return None, (
            "`docker` is not on PATH. This gate drives the daemon from the runner, so it cannot run "
            "anywhere the docker CLI is missing")
    except subprocess.TimeoutExpired as error:
        return None, "`{}` did not finish within {} s. Output so far:\n{}".format(
            " ".join(argv), timeout, excerpt(error.output))
    return completed.returncode, completed.stdout or ""


def remove_container(name):
    """Best effort. Never the reason a check fails; the workflow cleans up too."""
    docker(["rm", "-f", name], REMOVE_TIMEOUT)


def environment_flags(pairs):
    """A list of `VAR=value` strings as `-e VAR=value` pairs for a `docker run` argument list."""
    flags = []
    for pair in pairs:
        flags.extend(["-e", pair])
    return flags


def probe_report_rows(output, prefix):
    """Parse a probe's own report lines back into rows of this gate's report.

    Both probes print the same `ok   <target>` / `FAIL <target> -> <reason>` shape this file does, so
    their verdicts merge into one list instead of arriving as a single opaque "the probe failed".
    That matters for the same reason every other check here has one row per claim: a run that breaks
    four things should say four things.
    """
    rows = []
    for line in output.splitlines():
        if line.startswith("ok   "):
            rows.append((prefix + line[5:], None))
        elif line.startswith("FAIL "):
            target, _, reason = line[5:].partition(" -> ")
            rows.append((prefix + target, reason or "the probe reported FAIL with no reason"))
    return rows


def wait_for_markers(name, markers, budget):
    """Poll `docker logs` until EVERY marker has appeared, or the budget runs out.

    All of them, not the first: the DNS and HTTP markers come from two different threads, so their
    order is not fixed and returning on whichever arrived first would leave the other unproven while
    reporting success. Bounded in WALL CLOCK rather than in attempts, because each attempt shells out
    to `docker logs` with its own bound and an attempt-counted loop would multiply into minutes on a
    slow daemon.

    Returns (status, logs) from the last poll.
    """
    deadline = time.monotonic() + budget
    while True:
        status, logs = docker(["logs", name], LOGS_TIMEOUT)
        if status == 0 and all(marker in logs for marker in markers):
            return status, logs
        if time.monotonic() >= deadline:
            return status, logs
        time.sleep(BOOT_PAUSE)


def check_image_contract(image):
    """(a) What the image DECLARES: its command, where it runs, and that nothing wraps them."""
    rows = []
    target = "docker inspect {}".format(image)
    status, output = docker(["inspect", "--format", "{{json .Config}}", image], INSPECT_TIMEOUT)
    if status is None:
        # No exit code at all: the docker CLI is missing or the call ran out its bound. The message
        # from docker() already says which, and neither means what a non-zero exit means.
        return [(target, output)]
    if status != 0:
        return [(target, (
            "it exited {} — the tag does not exist on this daemon, so the build step and this step "
            "disagree about what was built. Output:\n{}".format(status, excerpt(output))))]
    try:
        config = json.loads(output)
    except ValueError as error:
        return [("parse the image config of {}".format(image), (
            "docker inspect returned something that is not JSON ({}): {}".format(
                error, excerpt(output))))]

    cmd = config.get("Cmd")
    rows.append((
        "the image's CMD is {}".format(EXPECTED_CMD),
        None if cmd == EXPECTED_CMD else (
            "it is {!r}. Production runs the image's own command and so does the boot check below — "
            "a silent change here means the gate and the deployment are describing two different "
            "programs".format(cmd))))

    # The ENTRYPOINT prepends itself to the CMD above, and that is the whole privilege drop: the
    # image runs `/entrypoint.sh python main.py`, the script starts as root, chowns the state
    # directory and `exec`s gosu to hand the process to uid 1000. Losing this line does not break
    # anything visibly — the CMD still runs, the service still serves, every other check here still
    # passes — it just serves as root again, which is precisely why it is pinned by value here and
    # cross-checked against PID 1's real uid in the service probe.
    entrypoint = config.get("Entrypoint")
    rows.append((
        "the image's ENTRYPOINT is {}".format(EXPECTED_ENTRYPOINT),
        None if entrypoint == EXPECTED_ENTRYPOINT else (
            "it is {!r}. That script is the only thing dropping this container from root to uid "
            "1000; without it the CMD runs on its own, as root, and nothing else in the image "
            "declares a user".format(entrypoint))))

    working_dir = config.get("WorkingDir")
    rows.append((
        "the image's WORKDIR is {}".format(APP_DIR),
        None if working_dir == APP_DIR else (
            "it is {!r}. Every path the app uses is relative — `main.py`, `src/`, `templates/` — so "
            "a moved working directory finds none of its own files, and the image probe's absence "
            "checks would be looking at the wrong tree".format(working_dir))))
    return rows


def check_config_guard(image, name):
    """(c) Started with NO configuration, the image refuses and says exactly what is missing.

    Run in the FOREGROUND so `docker run` hands back the container's own exit status. Both halves are
    checked — the message and the code — because either alone is satisfiable by the wrong thing: a
    process that printed the right text and exited 0 would be deployed and left running broken, and
    one that exited 1 silently sends an operator to read the source.
    """
    rows = []
    remove_container(name)
    status, output = docker(["run", "--name", name, image], GUARD_TIMEOUT)
    exit_target = "started with no configuration, the image exits non-zero"
    if status is None:
        # Timed out or docker is missing: no verdicts at all rather than a guessed one.
        reason = output
        rows.append((exit_target, reason))
        rows.append(("it prints {!r}".format(GUARD_HEADER), "not attempted: the run produced no exit code"))
        rows.append(("it prints {!r}".format(GUARD_MISSING_LINE), "not attempted: the run produced no exit code"))
        for variable in REQUIRED_VARIABLES:
            rows.append(("it names {} as missing".format(variable),
                         "not attempted: the run produced no exit code"))
        return rows, output

    rows.append((
        exit_target,
        None if status != 0 else (
            "it exited 0. A container that starts without its Proxmox credentials and reports "
            "success would be deployed and would serve an empty zone for the whole `.lc` network")))
    rows.append((
        "it prints {!r}".format(GUARD_HEADER),
        None if GUARD_HEADER in output else "the output does not contain it:\n{}".format(
            excerpt(output))))
    rows.append((
        "it prints {!r}".format(GUARD_MISSING_LINE),
        None if GUARD_MISSING_LINE in output else "the output does not contain it:\n{}".format(
            excerpt(output))))
    for variable in REQUIRED_VARIABLES:
        # Each variable gets its own row: an operator who is told about one missing variable at a
        # time comes back three times.
        rows.append((
            "it names {} as missing".format(variable),
            None if variable in output else (
                "the guard fired but never mentioned this variable, so whoever reads the message "
                "fixes part of the configuration and runs into the same wall again")))
    return rows, output


def start_serving_container(image, name):
    """Start the image with its REAL command and an unreachable PVE.

    NO PORT IS PUBLISHED — see the module docstring. The container is given credentials pointing at
    127.0.0.1 on purpose: that is the state the ensure_client() fix exists for, and the startup
    markers below are the receipt that the fix is still in the image.
    """
    target = "`docker run -d` starts the image with its own command"
    remove_container(name)
    status, output = docker(
        ["run", "-d", "--name", name] + environment_flags(SERVE_ENV) + [image],
        START_TIMEOUT)
    if status is None:
        return [(target, output)], False
    if status != 0:
        return [(target, "`docker run -d` exited {}:\n{}".format(status, excerpt(output)))], False
    return [(target, None)], True


def check_startup_markers(name, started):
    """(d) All three startup markers appear, with PVE unreachable.

    This is the regression check. Before ensure_client(), `build_client()` was the first statement of
    run() and proxmoxer authenticates in its constructor — so with no PVE to reach, the process died
    before any of these three lines was ever printed, and did so again on every restart.
    """
    if not started:
        reason = "not attempted: the serving container never started"
        return [("the log carries {!r}".format(marker), reason) for marker in STARTUP_MARKERS], ""

    status, logs = wait_for_markers(name, STARTUP_MARKERS, BOOT_BUDGET)
    if status is None:
        reason = "not attempted: `docker logs` produced no exit code — {}".format(logs)
        return [("the log carries {!r}".format(marker), reason) for marker in STARTUP_MARKERS], ""

    rows = []
    for marker in STARTUP_MARKERS:
        rows.append((
            "the log carries {!r}".format(marker),
            None if marker in logs else (
                "it never appeared within {} s. With PVE unreachable the process is supposed to "
                "start anyway and serve an empty zone; a missing marker here means it did not get "
                "this far, which for the DNS line means the `.lc` zone resolves nowhere".format(
                    BOOT_BUDGET))))
    return rows, logs


def run_probe(name, started, program, timeout, marker, expected_targets, prefix, label):
    """Feed one probe to `docker exec -i <name> python -u -` and merge its verdicts into ours.

    `-i` attaches stdin without asking for a tty (none is needed and none is available on a runner),
    the image's own interpreter runs the program, and `docker exec` propagates the command's exit
    status — which is what lets the two consistency rows below tell "the probe reported failures"
    apart from "the probe died before it could report anything".
    """
    exit_target = "the {} probe's exit status agrees with its own report".format(label)
    marker_target = "the {} probe ran to its end, reporting all {} targets".format(
        label, expected_targets)
    if not started:
        return [("the {} probe".format(label),
                 "not attempted: its container never started")], ""

    status, output = docker(["exec", "-i", name, "python", "-u", "-"], timeout, stdin_text=program)
    if status is None:
        # Timed out, or docker is missing. Either way there are no verdicts to merge.
        return [("the {} probe".format(label), output)], output

    rows = probe_report_rows(output, prefix)
    if not rows:
        # Exit status alone cannot be read here: a probe that printed nothing has told us nothing,
        # whatever it exited with. This is what a `docker exec` that could not start the interpreter
        # looks like, and what a truncated stdin looks like.
        return [("the {} probe".format(label), (
            "it produced no report lines at all, so none of its checks ran. `docker exec` exited "
            "{}. Output:\n{}".format(status, excerpt(output))))], output

    reported_failures = any(reason is not None for _, reason in rows)
    if status != 0 and not reported_failures:
        rows.append((exit_target, (
            "`docker exec` exited {} but every line the probe printed says ok — so it died after "
            "reporting and before finishing, and the report above is incomplete".format(status))))
    elif status == 0 and reported_failures:
        rows.append((exit_target, (
            "the probe printed FAIL lines yet exited 0. Its failures are supposed to leave through "
            "SystemExit(1); an exit of 0 here means they no longer do, and this gate would have "
            "gone green on them")))
    else:
        rows.append((exit_target, None))

    # Exact, not a substring of the marker alone: see the note on the EXPECTED_*_TARGETS constants.
    expected_line = "{}: {}/{} targets".format(marker, expected_targets, expected_targets)
    if expected_line in output:
        rows.append((marker_target, None))
    elif marker not in output:
        rows.append((marker_target, (
            "it never printed {!r}. The marker is on the probe's last line, so its absence means "
            "the program did not run to the end — a truncated stdin, or something that killed the "
            "interpreter mid-report".format(marker))))
    else:
        # It finished, but with a different number of verdicts than this gate expects. That is a gate
        # that has quietly started proving less, which is the failure mode nothing else here can see:
        # every row it DID print says ok, and the exit status is 0.
        summary = [line for line in output.splitlines() if line.startswith(marker)]
        rows.append((marker_target, (
            "it ran to the end but reported {!r} instead of {} targets. Either a check stopped "
            "emitting rows — in which case this gate is now proving less than it says it does and "
            "nothing else would have noticed — or one was added and the EXPECTED_*_TARGETS constant "
            "in this file needs updating".format(
                summary[0] if summary else "(unparseable)", expected_targets))))
    return rows, output


def check_container_alive(name, started):
    """(i) The serving container is still up after everything else has had its turn at it."""
    target = "the serving container is still running at the end of the gate"
    if not started:
        return [(target, "not attempted: it never started")]
    status, output = docker(
        ["inspect", "--format", "{{.State.Running}} {{.State.ExitCode}}", name], INSPECT_TIMEOUT)
    if status is None:
        return [(target, output)]
    if status != 0:
        return [(target, "`docker inspect` exited {}: {}".format(status, excerpt(output)))]
    state = output.strip()
    if state.startswith("true"):
        return [(target, None)]
    return [(target, (
        "it is not running any more (`Running ExitCode` = {!r}). It answered the probes and then "
        "stopped, which in production is a container the updater would restart into the same "
        "state".format(state)))]


def check_sigterm_shutdown(name, started):
    """(k) SIGTERM reaches PID 1 and it shuts ITSELF down instead of being killed.

    `docker stop` is exactly what a redeploy does: SIGTERM, wait out the grace period, then
    SIGKILL. So this check is the redeploy, run against the image before it can be pushed.

    An exit code of 0 means the signal was both delivered and acted on: /entrypoint.sh `exec`ed, so
    python is PID 1, AND src/app.py installed a handler that sets the Event its main loop waits on.
    Both are needed and the two failure codes below say which half went.

    137 is 128+9 — SIGKILL, sent because the grace period ran out with the process still alive.
    That is the shape of the bug this check was written for: PID 1 gets no default signal
    dispositions from the kernel, so a python process that installs no handler has SIGTERM DROPPED
    on it and does not even notice the stop. Nothing else in this gate can see that — the container
    is PID 1, runs as uid 1000 and serves both protocols perfectly right up to the moment it has to
    be killed.

    143 is 128+15 — SIGTERM arrived and terminated the process outright, i.e. it was delivered to
    something with the default disposition. On this image that means the handler is gone but python
    is no longer PID 1 either (a shell wrapper took the slot), because at PID 1 the same missing
    handler produces 137 instead.

    Either way the cost is the same and it is not abstract: the `.lc` zone resolves nowhere for the
    whole grace period on every single redeploy, instead of for the moment it takes the replacement
    container to bind :53.

    LAST of everything that touches the container, because it ENDS it. check_final_log() below
    still reads the log of a stopped container, and `docker rm -f` still removes one.
    """
    stop_target = "`docker stop` completes within the {} s grace period".format(SIGTERM_GRACE)
    code_target = "the serving container exits 0 on SIGTERM rather than being killed"
    if not started:
        reason = "not attempted: the serving container never started"
        return [(stop_target, reason), (code_target, reason)]

    status, output = docker(["stop", "-t", str(SIGTERM_GRACE), name], STOP_TIMEOUT)
    if status is None:
        # No exit code at all: the bound fired or docker is missing, and neither is a verdict about
        # the image. `docker stop` itself exits 0 even when it had to SIGKILL, so the exit code
        # below is the row that judges the shutdown; this one only says the call completed.
        return [(stop_target, output), (code_target, "not attempted: " + output)]
    if status != 0:
        reason = "`docker stop` exited {}:\n{}".format(status, excerpt(output))
        return [(stop_target, reason), (code_target, "not attempted: " + reason)]
    rows = [(stop_target, None)]

    status, output = docker(["inspect", "--format", "{{.State.ExitCode}}", name], INSPECT_TIMEOUT)
    if status is None:
        rows.append((code_target, output))
        return rows
    if status != 0:
        rows.append((code_target, "`docker inspect` exited {}: {}".format(status, excerpt(output))))
        return rows
    code = output.strip()
    rows.append((code_target, None if code == "0" else (
        "it exited {!r}. {} Both halves have to hold for a container to stop by itself: "
        "/entrypoint.sh must `exec` so python IS PID 1, and src/app.py must install a SIGTERM "
        "handler, because PID 1 is given no default signal dispositions and an unhandled signal "
        "there is dropped. Without them every redeploy takes the `.lc` zone down for the whole "
        "grace period".format(code, {
            "137": "That is 128+9: SIGKILL, sent because the {} s grace period ran out with the "
                   "process still alive — nothing acted on SIGTERM at all.".format(SIGTERM_GRACE),
            "143": "That is 128+15: SIGTERM terminated the process outright, so it reached "
                   "something running with the default disposition rather than a handler.",
        }.get(code, "That is neither a clean exit nor a signal this gate recognises.")))))
    return rows


def check_final_log(name, started):
    """(i) The log the container has BY NOW is free of tracebacks.

    Read fresh, at the end, rather than reusing the snapshot the boot wait returned: everything else
    in this gate has run against the container since then, and a crash provoked by one of the probes
    would be invisible in the older copy.

    One expected error line is NOT a traceback and is deliberately not treated as one: with PVE
    unreachable, ensure_client() logs `[Proxmox] Cannot build the API client, will keep retrying`
    once. That message is the fix working. A TRACEBACK, by contrast, means something escaped a
    handler that was supposed to contain it.
    """
    target = "the serving container's final log is free of tracebacks"
    if not started:
        return [(target, "not attempted: it never started")], ""
    status, logs = docker(["logs", name], LOGS_TIMEOUT)
    if status is None:
        return [(target, logs)], ""
    if status != 0:
        return [(target, "`docker logs` exited {}: {}".format(status, excerpt(logs)))], logs
    if TRACEBACK_MARKER in logs:
        return [(target, (
            "it contains {!r}. Something raised past a handler that was supposed to contain it; the "
            "transcript above has the whole log".format(TRACEBACK_MARKER)))], logs
    return [(target, None)], logs


def main():
    image = os.environ.get(IMAGE_ENV)
    if not image:
        print("{} is not set: this gate tests the image it is given and has no default, because a "
              "default would silently gate whichever image happened to be on the daemon".format(
                  IMAGE_ENV))
        raise SystemExit(1)
    name = os.environ.get(NAME_ENV)
    if not name:
        print("{} is not set: this gate names every container it starts after it, and a default "
              "would both hide containers from the workflow's cleanup step and make two concurrent "
              "runs collide on one name".format(NAME_ENV))
        raise SystemExit(1)

    rows = []
    transcripts = []

    rows.extend(check_image_contract(image))

    try:
        guard_rows, guard_output = check_config_guard(image, name + GUARD_SUFFIX)
        transcripts.append(("the image started with no configuration at all", guard_output))
        rows.extend(guard_rows)

        serve_rows, serve_started = start_serving_container(image, name + SERVE_SUFFIX)
        rows.extend(serve_rows)

        marker_rows, _boot_logs = check_startup_markers(name + SERVE_SUFFIX, serve_started)
        rows.extend(marker_rows)

        image_probe_rows, image_probe_output = run_probe(
            name + SERVE_SUFFIX, serve_started, IMAGE_PROBE, IMAGE_PROBE_TIMEOUT,
            IMAGE_PROBE_MARKER, EXPECTED_IMAGE_PROBE_TARGETS, IMAGE_PROBE_ROW_PREFIX, "image")
        transcripts.append(("the image probe, from inside the container", image_probe_output))
        rows.extend(image_probe_rows)

        service_probe_rows, service_probe_output = run_probe(
            name + SERVE_SUFFIX, serve_started, SERVICE_PROBE, SERVICE_PROBE_TIMEOUT,
            SERVICE_PROBE_MARKER, EXPECTED_SERVICE_PROBE_TARGETS, SERVICE_PROBE_ROW_PREFIX,
            "service")
        transcripts.append(("the service probe, from inside the container", service_probe_output))
        rows.extend(service_probe_rows)

        # After the probes on purpose: "the container is still up" is only worth anything once
        # everything else has had its turn at it. Before the stop below for the same reason — this
        # row is about a container that is supposed to be alive.
        rows.extend(check_container_alive(name + SERVE_SUFFIX, serve_started))

        # Ends the container, so it goes after everything that needed it alive and before the two
        # steps that do not: the final log and the cleanup both work on a stopped container.
        rows.extend(check_sigterm_shutdown(name + SERVE_SUFFIX, serve_started))

        # LAST, and that is the reason it exists: the log the container has at this point is the
        # whole run rather than the snapshot the boot wait returned.
        final_rows, final_logs = check_final_log(name + SERVE_SUFFIX, serve_started)
        rows.extend(final_rows)
        transcripts.append(("the serving container", final_logs))
    finally:
        # Both, unconditionally. When a bound fires inside docker() it kills the docker CLIENT on the
        # runner, not the container on the daemon, so a hung run would otherwise sit here pinning the
        # image until somebody noticed. The workflow removes the same names again under
        # `if: always()`, which covers this whole script being killed by the step timeout.
        for suffix in ALL_SUFFIXES:
            remove_container(name + suffix)

    # The transcripts first, the verdicts last: in a CI log the verdicts are what somebody scrolls to
    # the bottom for, and the containers' own output is what turns a one-line verdict into a
    # diagnosis.
    for label, text in transcripts:
        print("")
        print("--- {} ---".format(label))
        print(excerpt(text).rstrip() or "(no output)")
    print("")
    print("--- results ---")

    # Before a single verdict is printed: the NUMBER of verdicts is itself one. A check_* that
    # stopped emitting rows takes its own verdicts out of the report and takes nothing red with them,
    # so the run would end `smoke ok: 34/34`, exit 0, and have every printed row saying ok with two
    # claims silently no longer made.
    #
    # ONLY on a run where nothing else failed, and that is not laziness about the arithmetic. A
    # failing check_* legitimately reports fewer rows than its happy path — check_image_contract
    # emits 1 instead of 3 when `docker inspect` cannot answer, run_probe 1 instead of 13 when its
    # exec timed out — so on an already-red run this row would fire too, on top of the real failure,
    # and read as though the GATE were broken. The fault it exists to catch is invisible on a red run
    # and decisive on a green one, which is exactly where it is still reported.
    if len(rows) != EXPECTED_TOTAL_TARGETS and not any(reason is not None for _, reason in rows):
        rows.append((
            "this gate produced all {} of the verdicts it is supposed to".format(
                EXPECTED_TOTAL_TARGETS),
            "it produced {}, and every one of them says ok. Either a check stopped emitting rows — "
            "in which case this gate is now proving less than it says it does and nothing else here "
            "would have noticed — or one was added or removed and EXPECTED_TOTAL_TARGETS needs "
            "updating".format(len(rows))))

    failures = []
    for target, reason in rows:
        if reason is None:
            print("ok   {}".format(target))
        else:
            print("FAIL {} -> {}".format(target, reason))
            failures.append(target)

    if failures:
        print("")
        print("smoke FAILED: {}/{} targets broken:".format(len(failures), len(rows)))
        for target in failures:
            print("  - {}".format(target))
        raise SystemExit(1)

    print("")
    print("smoke ok: {}/{} targets".format(len(rows), len(rows)))


if __name__ == "__main__":
    main()
