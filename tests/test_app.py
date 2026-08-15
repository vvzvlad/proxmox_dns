"""Startup invariants of src/app.py.

All three tests here defend ONE property, from three directions: whatever the
Proxmox side does while the process is starting, the DNS and HTTP servers still
come up. This service answers DNS for the whole internal `.lc` zone, so a
startup that dies before those two threads exist does not degrade the zone — it
removes it, and under `restart: unless-stopped` it does so in a loop.

The property is easy to lose because proxmoxer authenticates EAGERLY: ProxmoxAPI
builds a ProxmoxHTTPAuth, whose __init__ posts to /access/ticket. So
`build_client()` is a network call, and a PVE that is down or rejecting
credentials raises out of the constructor, not out of the first request.
"""

import threading

import pytest

from src import app, state

# How long to wait for a server thread to report in. Generous: it only has to
# cover thread scheduling, and a failing run pays this once.
STARTUP_WAIT = 5.0


class _StopLoop(BaseException):
    """Sentinel used to unwind the infinite loops in src/app.py.

    Derived from BaseException RATHER THAN Exception on purpose: start_thread()
    catches Exception to restart a crashed server, so a normal exception would be
    swallowed and the thread would immediately spin the loop again. BaseException
    passes through it and lets a test end the loop it is driving.
    """


class _FakeClock:
    """Stand-in for the `time` module inside src/app.py.

    Injected as `app.time`, so it replaces the module reference in this one
    module and nothing else in the process. It ends the loop it is driving after
    `ticks` sleeps, and advances a virtual clock by the slept amount so
    time.time() moves the way the updater expects without any real waiting.
    """

    def __init__(self, ticks):
        self._ticks_left = ticks
        self._now = 0.0

    def sleep(self, seconds):
        if self._ticks_left <= 0:
            raise _StopLoop
        self._ticks_left -= 1
        self._now += seconds

    def time(self):
        return self._now


def _isolate_module_state(monkeypatch):
    """Reset the client cache and the zone that src/app.py keeps at module level.

    monkeypatch restores both afterwards, so one test's client cannot leak into
    the next one's ensure_client() and make a retry look like a success.
    """
    monkeypatch.setattr(app, "_proxmox", None)
    monkeypatch.setattr(app, "_client_error_logged", False)
    servers = []
    monkeypatch.setattr(state, "servers_list", servers)
    return servers


def _parked_target(reported=None):
    """A stand-in for one of the three loops run() hands to a thread.

    Sets `reported` if given, then blocks forever — which is what the real
    targets do, since the UDP loop, serve_forever() and the updater's `while
    True` never return. Returning instead would send start_thread() straight back
    round its own `while True` and spin the CPU. The thread is a daemon parked on
    an Event, so it costs nothing and dies with the interpreter.

    The updater gets one of these too in the two run() tests below. Those tests
    are about the servers being reached; letting the real updater run would put
    the fake clock on a second thread, where its _StopLoop would surface as an
    unhandled exception in a thread rather than as anything either test asserts.
    The updater has its own test at the bottom of this file.
    """
    parked = threading.Event()

    def target():
        if reported is not None:
            reported.set()
        parked.wait()

    return target


def test_run_starts_dns_and_http_when_the_proxmox_client_cannot_be_built(monkeypatch):
    """The regression: an unreachable PVE at startup must still leave the zone served.

    Before ensure_client(), run() called build_client() on its first line, so the
    eager authentication above raised straight out of run() — before any of the
    three threads existed. The process died, the container restarted, and it died
    again: `.lc` resolved nowhere for as long as PVE was down.
    """
    dns_started = threading.Event()
    http_started = threading.Event()

    def unreachable_pve():
        raise ConnectionError("connection refused: /access/ticket")

    _isolate_module_state(monkeypatch)
    monkeypatch.setattr(app, "build_client", unreachable_pve)
    monkeypatch.setattr(app, "start_dns_server", _parked_target(dns_started))
    monkeypatch.setattr(app, "start_http_server", _parked_target(http_started))
    monkeypatch.setattr(app, "update_dns_periodically", _parked_target())
    # 0 ticks: the first sleep run() reaches — the one in its reporting loop, after
    # the threads are started — ends the call.
    monkeypatch.setattr(app, "time", _FakeClock(ticks=0))

    with pytest.raises(_StopLoop):
        app.run()

    assert dns_started.wait(STARTUP_WAIT), (
        "run() returned without ever reaching start_dns_server: an unreachable PVE "
        "at startup takes the whole .lc zone down with it")
    assert http_started.wait(STARTUP_WAIT), (
        "run() returned without ever reaching start_http_server: the status page and "
        "the compose healthcheck it answers are both gone")


def test_run_starts_dns_and_http_when_the_first_domain_fetch_raises(monkeypatch):
    """The same invariant one step later: a client that builds, then a fetch that throws.

    get_domains() degrades an unreachable API to None, but only for the two
    exception types it catches. proxmoxer's AuthenticationError derives from plain
    Exception and is neither of them, so it reaches run() — which is why
    initial_domains() guards the call rather than trusting it.
    """
    dns_started = threading.Event()
    http_started = threading.Event()

    def rejected_credentials(_proxmox):
        raise RuntimeError("Couldn't authenticate user: dns@pve")

    _isolate_module_state(monkeypatch)
    monkeypatch.setattr(app, "build_client", lambda: object())
    monkeypatch.setattr(app, "get_domains", rejected_credentials)
    monkeypatch.setattr(app, "start_dns_server", _parked_target(dns_started))
    monkeypatch.setattr(app, "start_http_server", _parked_target(http_started))
    monkeypatch.setattr(app, "update_dns_periodically", _parked_target())
    monkeypatch.setattr(app, "time", _FakeClock(ticks=0))

    with pytest.raises(_StopLoop):
        app.run()

    assert dns_started.wait(STARTUP_WAIT), (
        "run() died on the initial domain fetch and never started the DNS server")
    assert http_started.wait(STARTUP_WAIT), (
        "run() died on the initial domain fetch and never started the HTTP server")


def test_updater_retries_a_failed_client_and_fills_the_zone_once_pve_answers(monkeypatch):
    """The other half of the fix: the updater keeps trying, and the zone fills up.

    Starting without a client is only survivable if something later builds one.
    This drives the updater through two failed attempts and a successful third,
    and then one more tick to show the built client is reused rather than
    rebuilt on every pass.
    """
    attempts = []
    client = object()
    domains = [{"domain": "foo.lc", "ipv4": "10.0.0.5", "ipv6": "fe80::1"}]

    def pve_up_on_the_third_try():
        attempts.append(None)
        if len(attempts) < 3:
            raise ConnectionError("connection refused: /access/ticket")
        return client

    def inventory(proxmox):
        assert proxmox is client, "the updater polled with something other than the built client"
        return frozenset({(100, "foo-bar", "node1", "running")})

    def all_domains(proxmox):
        assert proxmox is client, "the updater fetched with something other than the built client"
        return list(domains)

    servers = _isolate_module_state(monkeypatch)
    monkeypatch.setattr(app, "build_client", pve_up_on_the_third_try)
    monkeypatch.setattr(app, "get_vm_inventory", inventory)
    monkeypatch.setattr(app, "get_domains", all_domains)
    # Four ticks: two that find PVE down, one that connects and refreshes, and a
    # fourth that must reuse the client. The fifth sleep ends the loop.
    monkeypatch.setattr(app, "time", _FakeClock(ticks=4))

    with pytest.raises(_StopLoop):
        app.update_dns_periodically()

    assert len(attempts) == 3, (
        f"expected two failed builds and one that took, got {len(attempts)} attempts: "
        "either the updater gave up after the first failure, or it rebuilds the client "
        "on every tick instead of caching it")
    assert servers == domains, (
        f"the zone was not refreshed once PVE answered: {servers!r}")
