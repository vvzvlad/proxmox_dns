import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer

from src import state
from src.http_server import StatusRequestHandler

# One entry as the zone really holds it: what src/proxmox.py stamps on it and what the
# merge ranks on, `vmid` included. Both endpoints are built from entries of this shape,
# and neither is authenticated.
# The vmid is deliberately a value that appears nowhere else in a rendered page, so
# "it is not on the page" can be asserted as a plain substring test.
ENTRY = {"domain": "foo.lc", "ipv4": "10.0.0.5", "ipv6": "::1", "host": "pve1.example",
         "vmid": 7777, "status": "running"}


def _serve():
    server = ThreadingHTTPServer(("127.0.0.1", 0), StatusRequestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def test_health_endpoint(monkeypatch):
    monkeypatch.setattr(state, "servers_list", [])
    server = _serve()
    try:
        port = server.server_address[1]
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=5) as r:
            assert r.status == 200
    finally:
        server.shutdown()


def test_root_returns_single_valid_response(monkeypatch):
    monkeypatch.setattr(state, "servers_list", [dict(ENTRY)])
    server = _serve()
    try:
        port = server.server_address[1]
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as r:
            body = r.read().decode()
            assert r.status == 200
            assert "foo.lc" in body
            # Which PVE host the name came from. With several hosts merged into one
            # zone this page is where a name served by two of them becomes visible,
            # and without the column the page cannot show a collision at all.
            assert "pve1.example" in body, (
                f"the status page does not say which host the domain came from:\n{body}")
            # And the run state, which is what explains a name resolving to the
            # 0.0.0.0 sentinel without anybody having to read the source.
            assert "running" in body, (
                f"the status page does not show the guest's state:\n{body}")
            # The same projection /json is held to, for the same reason: this page is
            # published on :8076 and routed by Traefik, and a vmid identifies a guest
            # inside somebody's Proxmox.
            assert "7777" not in body, (
                f"the vmid reached the public status page:\n{body}")
    finally:
        server.shutdown()


def test_json_publishes_an_explicit_set_of_fields(monkeypatch):
    """What an unauthenticated endpoint carries is a decision, not a side effect.

    Serialising the entry wholesale means every field ever added to it — by the merge,
    by src/proxmox.py, by anything — is published the moment it appears, silently and
    with nobody having chosen it. Today that is `vmid`; the point is that the next one
    needs no code change to leak.
    """
    monkeypatch.setattr(state, "servers_list", [dict(ENTRY)])
    server = _serve()
    try:
        port = server.server_address[1]
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/json", timeout=5) as r:
            assert r.status == 200
            payload = json.loads(r.read().decode())
    finally:
        server.shutdown()

    assert payload == [{"domain": "foo.lc", "host": "pve1.example", "ipv4": "10.0.0.5",
                        "ipv6": "::1", "status": "running"}], (
        f"/json served {payload!r} rather than the fields this endpoint publishes")
    assert "vmid" not in payload[0], (
        "the entry's vmid is on an unauthenticated page: it identifies a guest inside "
        "somebody's Proxmox and tells a reader of a status page nothing")


def test_vm_names_are_escaped_rather_than_rendered(monkeypatch):
    """Every value on this page came from a VM name somebody typed into Proxmox.

    The rows are built by interpolating those values into HTML, so a guest called
    `<script>...` would be rendered as markup by anyone opening the status page.
    """
    monkeypatch.setattr(
        state,
        "servers_list",
        [{"domain": "<script>alert(1)</script>.lc", "ipv4": "10.0.0.5", "ipv6": "::1",
          "host": "pve1.example"}],
    )
    server = _serve()
    try:
        port = server.server_address[1]
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as r:
            body = r.read().decode()
            assert "<script>" not in body, f"a VM name reached the page as markup:\n{body}"
            assert "&lt;script&gt;" in body, f"the name was dropped rather than escaped:\n{body}"
    finally:
        server.shutdown()
