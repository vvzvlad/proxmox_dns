"""Smoke gate for the proxmox_dns image, run on the CI runner against an already-built image.

It sits between `docker build` and `docker push`: the deployed stack carries
`io.portainer.update.enable`, so whatever lands on `:latest` is redeployed with nobody in between.
The image answers DNS for the whole internal `.lc` zone.

THE SPLIT
---------
The OUTER half is this file, run as `python3 ci/smoke.py` on the runner and driving `docker`. It
checks the container as an object: `docker inspect`, the real command's log, the configuration
guard, liveness and shutdown.

The two INNER halves are probes kept here as string constants and fed to
`docker exec -i <name> python -u -`. The IMAGE probe checks files and dependencies inside the image;
the SERVICE probe checks who the running process is and whether it serves HTTP and DNS.

No port is published: act_runner runs this job in its own container, so the job's 127.0.0.1 is not
the daemon's and a published port would be unreachable. Everything internal goes through
`docker exec`, inside the container's own network namespace.

`docker exec` bypasses ENTRYPOINT and runs as the image's `Config.User`, which is unset, so probes
run as root while the service runs as uid 1000 (/entrypoint.sh chowns the state directory and
`exec`s gosu). Hence the non-root check reads PID 1's uid, and the contract check pins ENTRYPOINT to
an exact value.

No capability is granted: docker sets net.ipv4.ip_unprivileged_port_start=0 inside a container, so
uid 1000 binds 53 and 80 unprivileged, as in production.

THE TEST BED: NO PROXMOX
------------------------
The serving container gets TWO PROXMOX_HOSTS entries at two different RFC 5737 addresses where no
PVE answers. Unreachable: nothing on the way to binding the sockets may wait for Proxmox (the client
is built lazily by `ensure_client()` and the startup fetch runs under a deadline), so the three
startup markers must still appear (check (d)). Two and distinct: the service runs with several
hosts, and distinct addresses let check (l) count which hosts are polled.

An empty zone also makes the DNS check exact: with no VMs known, src/dns_server.py answers NXDOMAIN.

THE CHECKS
----------
* (a) the declared contract: CMD, WORKDIR and the ENTRYPOINT that drops privileges. Outer half.
* (b) `curl` is present and runs: the compose healthcheck uses it, and the Portainer updater rolls
      the image back if it does not see `healthy` within 120 s. Image probe.
* (c) the configuration guard refuses: with no environment the image names the required variable
      and exits non-zero. Outer half.
* (d) the real command starts and logs all three startup markers with PVE unreachable. Outer half.
* (e) the HTTP status server answers /health, /json, / and a 404 for anything else. Service probe.
* (f) the DNS server answers a real UDP query on 127.0.0.1:53 for an A and a PTR question (PTR takes
      a separate branch in src/dns_server.py). Service probe.
* (g) .dockerignore kept tests/, .env, .venv and .gitea/ out of the image. Image probe.
* (h) the runtime dependencies import: dns, proxmoxer, pydantic_settings, requests. Image probe.
* (i) the container is still alive once everything else has run, and its final log, after (k) has
      stopped it, carries no traceback. Outer half.
* (j) PID 1 serves as uid 1000, not root. (a) cannot see this: the image keeps declaring its
      ENTRYPOINT whatever the script does. Service probe, the only place PID 1 can be read.
* (k) `docker stop` stops it with exit 0 within the grace period. Requires both that
      /entrypoint.sh `exec`s (python is PID 1 and receives SIGTERM) and that src/app.py installs a
      handler (PID 1 has no default signal dispositions, so an unhandled SIGTERM is dropped). Runs
      last of everything that touches the container, because it ends it. Outer half.
* (l) every configured host is polled: the service attributes each failure to its host, so both
      names must appear in the log. Catches a loop over `_hosts` reduced to `_hosts[0]`. Runs right
      after (d), off the same log snapshot. Outer half.

Invariants:

* Failures leave through SystemExit, never `assert`, on all three sides: asserts vanish under
  PYTHONOPTIMIZE=1.
* Every check runs before the run is judged, so one run shows all breakage. A check that cannot run
  reports FAILED and is never skipped. Probe report lines are parsed back into this gate's report.

Nothing here holds a credential: the addresses are RFC 5737 documentation addresses and the token is
a literal, which is what lets the same gate run on a pull request.
"""

import json
import os
import subprocess
import time

# The tag to test. Required rather than defaulted: a default would let a mistyped `env:` block in a
# workflow silently gate some other image that happens to be on the daemon.
IMAGE_ENV = "SMOKE_IMAGE"
# Base name for every container this gate starts. The workflows put the run id in it so concurrent
# runs on the shared daemon do not collide (remove_container() would delete another run's container).
# Required, not defaulted: the workflow's `if: always()` cleanup builds the same names from it.
NAME_ENV = "SMOKE_NAME"

GUARD_SUFFIX = "-guard"
SERVE_SUFFIX = "-serve"
# Kept in step with the cleanup step in both workflows.
ALL_SUFFIXES = (GUARD_SUFFIX, SERVE_SUFFIX)

# --- The image's declared contract -------------------------------------------------------------
APP_DIR = "/app"
EXPECTED_CMD = ["python", "main.py"]
# Pinned to an exact value: it is what drops root, and every other check reaches the container
# through `docker exec`, which bypasses it.
EXPECTED_ENTRYPOINT = ["/entrypoint.sh"]

# --- The three startup markers ------------------------------------------------------------------
# All three are logged at CRITICAL by src/app.py, src/dns_server.py and src/http_server.py, so they
# survive any LOG_LEVEL. The DNS and HTTP ones come from their own threads, so their order is not
# fixed and nothing here reads them positionally.
STARTUP_MARKER = "ProxDNS server started"
DNS_MARKER = "[DNS] Server run on port 53/udp on 0.0.0.0..."
HTTP_MARKER = "[HTTP] Server started on port 80..."
STARTUP_MARKERS = (STARTUP_MARKER, DNS_MARKER, HTTP_MARKER)

# --- What the configuration guard must say ------------------------------------------------------
# src/config_errors.py prints this block to stderr and raises SystemExit(1) when a required variable
# is missing. The one required variable is PROXMOX_HOSTS, checked by name: the guard must say what is
# missing.
GUARD_HEADER = "Configuration error in environment / .env:"
GUARD_MISSING_LINE = "Missing required variable(s):"
REQUIRED_VARIABLES = ("PROXMOX_HOSTS",)

# --- The environment the serving container gets -------------------------------------------------
# Two entries, because the service polls several independent hosts (a thread, client and slice of
# the zone each). Different addresses, so each host's failure line is identifiable and
# check_every_host_is_polled() can tell all hosts from `_hosts[0]` only.
#
# RFC 5737 addresses (TEST-NET-1, TEST-NET-2) route nowhere: every request times out at proxmoxer's
# 5 s rather than being refused. Hosts are fetched concurrently, so the boot pays one timeout. The
# token authenticates nothing.
SERVE_HOSTS = ("192.0.2.1", "198.51.100.1")
SERVE_ENV = [
    "PROXMOX_HOSTS=" + json.dumps([
        {"host": address, "user": "smoke@pve", "token_name": "smoke-{}".format(index),
         "token_value": "not-a-real-token"}
        for index, address in enumerate(SERVE_HOSTS, start=1)]),
]

TRACEBACK_MARKER = "Traceback (most recent call last)"

# --- Probe markers and their exact target counts ------------------------------------------------
# Each probe prints its marker with a count on its last line. The count is compared exactly, so a
# probe that silently stopped emitting rows still fails.
IMAGE_PROBE_MARKER = "proxmox_dns image probe ok"
SERVICE_PROBE_MARKER = "proxmox_dns service probe ok"
EXPECTED_IMAGE_PROBE_TARGETS = 11
# 1 identity + 2 /health + 2 /json + 2 / + 1 404 + 2 per DNS question, A and PTR.
EXPECTED_SERVICE_PROBE_TARGETS = 12

IMAGE_PROBE_ROW_PREFIX = "[in-image] "
SERVICE_PROBE_ROW_PREFIX = "[in-container] "

# Total verdicts a healthy run ends with, checked against the real count before the summary is
# printed. Outer half: 3 contract + 4 config guard (3 fixed rows + one per required variable)
# + 1 serving start + 3 startup markers + 1 alive + 2 SIGTERM shutdown + 1 clean log = 15, plus
# one row per configured host for the poll check. Each probe contributes its own targets plus the
# two consistency rows run_probe appends (its exit status, and that it ran to its end).
EXPECTED_OUTER_TARGETS = 15 + len(SERVE_HOSTS)
EXPECTED_TOTAL_TARGETS = (
    EXPECTED_OUTER_TARGETS
    + EXPECTED_IMAGE_PROBE_TARGETS + 2
    + EXPECTED_SERVICE_PROBE_TARGETS + 2)

# --- Bounds -------------------------------------------------------------------------------------
# Every docker call is bounded, so a hung daemon surfaces as a named failure rather than as a killed
# step.
INSPECT_TIMEOUT = 30
REMOVE_TIMEOUT = 30
GUARD_TIMEOUT = 60
START_TIMEOUT = 60
LOGS_TIMEOUT = 30
IMAGE_PROBE_TIMEOUT = 120
SERVICE_PROBE_TIMEOUT = 120
# Grace period for `docker stop` in check (k): generous so a process that is shutting down is not
# reported as deaf; a correct image needs a fraction of it. Not the 45 s from docker-compose.yml,
# which covers a stop during the startup fetch; this gate stops a container long past startup.
SIGTERM_GRACE = 20
# Must exceed SIGTERM_GRACE, or the client would be killed while the daemon still waits out the
# grace period.
STOP_TIMEOUT = 60

# Wall-clock budget for all three startup markers on a cold runner: imports, the startup fetch
# (capped by INITIAL_FETCH_DEADLINE at 10 s) and binding two sockets.
BOOT_BUDGET = 60
BOOT_PAUSE = 0.5
# The same, for each host's first failure line, which may arrive after the markers: the startup
# fetch abandons a host at INITIAL_FETCH_DEADLINE, and its updater thread retries afterwards.
HOST_FAILURE_BUDGET = 45

EXCERPT_CHARS = 4000


# ================================================================================================
# The IMAGE probe: files and dependencies inside the image.
# ================================================================================================
# Runs via `docker exec` in the serving container: its real command survives an unreachable PVE,
# so no separate idle container is needed.
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
# A name in the served zone that no VM can be called, and a PTR for a TEST-NET-3 address. With an
# unreachable PVE the domain list is empty, so src/dns_server.py must answer NXDOMAIN to both.
# TEST-NET-3 rather than the TEST-NET-1 this used to ask about: TEST-NET-1 is now where one of the
# configured PVE hosts lives, and a question about that address would read as though it were about
# the host rather than about an address nothing in the zone has.
UNKNOWN_NAME = "nothing-here-smoke.lc"
UNKNOWN_PTR = "1.113.0.203.in-addr.arpa"


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


def satisfied(logs, marker):
    """Is one requirement met? A string must appear; a tuple is met by ANY of its strings.

    The tuple form is for a claim with several legitimate spellings — "this host reported a
    failure" is true of four different messages, depending on which layer noticed first.
    """
    if isinstance(marker, tuple):
        return any(alternative in logs for alternative in marker)
    return marker in logs


def wait_for_markers(name, markers, budget):
    """Poll `docker logs` until EVERY marker has appeared, or the budget runs out.

    All of them: the DNS and HTTP markers come from different threads in no fixed order. Bounded in
    wall clock rather than attempts, since each attempt has its own `docker logs` bound.

    Returns (status, logs) from the last poll.
    """
    deadline = time.monotonic() + budget
    while True:
        status, logs = docker(["logs", name], LOGS_TIMEOUT)
        if status == 0 and all(satisfied(logs, marker) for marker in markers):
            return status, logs
        if time.monotonic() >= deadline:
            return status, logs
        time.sleep(BOOT_PAUSE)


def host_failure_markers(address):
    """Every line this service prints when ONE host does not answer, for that host.

    Any one proves the host was polled: src/proxmox.py and src/app.py each stamp the host on two
    error paths, and the startup fetch and the updater race, so any of the four may come first.
    """
    return (
        "[Proxmox] {}: failed to list nodes".format(address),
        "[Proxmox] {}: failed to query cluster resources".format(address),
        "[Proxmox] {}: initial domain fetch failed".format(address),
        "[Proxmox] {}: cannot build the API client".format(address),
    )


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

    # The ENTRYPOINT is the whole privilege drop (`/entrypoint.sh python main.py` execs gosu to uid
    # 1000). Losing it breaks nothing visible, so it is pinned by value here and cross-checked
    # against PID 1's uid in the service probe.
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

    Run in the foreground so `docker run` returns the container's exit status. Both the message and
    the non-zero code are checked.
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
        # One row per required variable: the guard must name which one is missing.
        rows.append((
            "it names {} as missing".format(variable),
            None if variable in output else (
                "the guard fired but never mentioned this variable, so whoever reads the message "
                "fixes part of the configuration and runs into the same wall again")))
    return rows, output


def start_serving_container(image, name):
    """Start the image with its REAL command and an unreachable PVE.

    No port is published; the two unroutable PROXMOX_HOSTS entries are explained in the module
    docstring.
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

    Asserts that nothing on the way to binding the sockets waits for Proxmox to answer.
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


def check_every_host_is_polled(name, started, boot_logs):
    """(l) EVERY configured host is really polled, not just the first one.

    Polling only `_hosts[0]` looks healthy everywhere else in this gate; only the missing name of
    the other host shows it, which is why the addresses are distinct.

    `boot_logs` is check (d)'s snapshot, which usually already carries both hosts' failures; the
    bounded wait covers a failure that arrives later.
    """
    targets = ["the log carries a failure attributed to the configured host {}".format(address)
               for address in SERVE_HOSTS]
    if not started:
        reason = "not attempted: the serving container never started"
        return [(target, reason) for target in targets]

    requirements = [host_failure_markers(address) for address in SERVE_HOSTS]
    logs = boot_logs or ""
    if not all(satisfied(logs, requirement) for requirement in requirements):
        status, logs = wait_for_markers(name, requirements, HOST_FAILURE_BUDGET)
        if status is None:
            reason = "not attempted: `docker logs` produced no exit code — {}".format(logs)
            return [(target, reason) for target in targets]

    rows = []
    for target, address in zip(targets, SERVE_HOSTS):
        rows.append((
            target,
            None if satisfied(logs, host_failure_markers(address)) else (
                "nothing in the log names it within {} s, while the other configured host is all "
                "over it. Every host is supposed to be polled on a thread of its own, so a host "
                "that never appears is a host that is never asked — its guests would be missing "
                "from the zone in production, silently and for ever".format(HOST_FAILURE_BUDGET))))
    return rows


def run_probe(name, started, program, timeout, marker, expected_targets, prefix, label):
    """Feed one probe to `docker exec -i <name> python -u -` and merge its verdicts into ours.

    `-i` attaches stdin without a tty. `docker exec` propagates the exit status, which lets the two
    consistency rows below tell "reported failures" from "died before reporting".
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
        # A probe that printed nothing has told us nothing, whatever it exited with (interpreter
        # failed to start, or truncated stdin).
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
        # Finished with a different number of verdicts than expected: a check stopped emitting rows
        # or one was added.
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

    `docker stop` is what a redeploy does. Exit 0 means /entrypoint.sh `exec`ed (python is PID 1)
    and src/app.py installed a handler that sets the Event its main loop waits on.

    137 (128+9): SIGKILL after the grace period; PID 1 has no default signal dispositions, so with
    no handler SIGTERM is dropped. 143 (128+15): SIGTERM hit a process with the default disposition,
    i.e. the handler is gone and python is not PID 1 (a shell wrapper took the slot).

    Runs last of everything that touches the container, because it ends it. check_final_log() and
    `docker rm -f` still work on a stopped container.
    """
    stop_target = "`docker stop` completes within the {} s grace period".format(SIGTERM_GRACE)
    code_target = "the serving container exits 0 on SIGTERM rather than being killed"
    if not started:
        reason = "not attempted: the serving container never started"
        return [(stop_target, reason), (code_target, reason)]

    status, output = docker(["stop", "-t", str(SIGTERM_GRACE), name], STOP_TIMEOUT)
    if status is None:
        # No exit code: the bound fired or docker is missing. `docker stop` exits 0 even after a
        # SIGKILL, so the container's exit code below is what judges the shutdown.
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

    Read fresh at the end, so a crash provoked by a probe is visible.

    The expected `[Proxmox] <host>: failed to ...` lines from the startup fetch and the updater are
    not tracebacks; check (l) relies on them. A traceback means something escaped a handler.
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

        marker_rows, boot_logs = check_startup_markers(name + SERVE_SUFFIX, serve_started)
        rows.extend(marker_rows)

        # Straight after the markers, and reusing their snapshot: by the time all three are
        # printed the startup fetch has been out at both hosts and failed at both.
        rows.extend(check_every_host_is_polled(name + SERVE_SUFFIX, serve_started, boot_logs))

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

        # After the probes and before the stop below.
        rows.extend(check_container_alive(name + SERVE_SUFFIX, serve_started))

        # Ends the container, so it goes after everything that needed it alive and before the two
        # steps that do not: the final log and the cleanup both work on a stopped container.
        rows.extend(check_sigterm_shutdown(name + SERVE_SUFFIX, serve_started))

        # Last: the log now covers the whole run, not the boot snapshot.
        final_rows, final_logs = check_final_log(name + SERVE_SUFFIX, serve_started)
        rows.extend(final_rows)
        transcripts.append(("the serving container", final_logs))
    finally:
        # Both, unconditionally: a bound firing in docker() kills the client, not the container.
        # The workflow removes the same names again under `if: always()`.
        for suffix in ALL_SUFFIXES:
            remove_container(name + suffix)

    # Transcripts first, verdicts last, where a CI log reader scrolls to.
    for label, text in transcripts:
        print("")
        print("--- {} ---".format(label))
        print(excerpt(text).rstrip() or "(no output)")
    print("")
    print("--- results ---")

    # The number of verdicts is itself a verdict: a check_* that stopped emitting rows would
    # otherwise leave an all-ok report. Checked only on an otherwise green run, because failing
    # checks legitimately emit fewer rows than their happy path.
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
