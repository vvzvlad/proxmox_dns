import threading
import urllib.request
from http.server import ThreadingHTTPServer

from src import state
from src.http_server import StatusRequestHandler


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
    monkeypatch.setattr(
        state,
        "servers_list",
        [{"domain": "foo.lc", "ipv4": "10.0.0.5", "ipv6": "::1"}],
    )
    server = _serve()
    try:
        port = server.server_address[1]
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as r:
            body = r.read().decode()
            assert r.status == 200
            assert "foo.lc" in body
    finally:
        server.shutdown()
