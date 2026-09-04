import html
import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from src import state
from src.logging_setup import logger
from src.settings import settings

# The fields these pages publish, and the only ones. Both endpoints are
# UNAUTHENTICATED — docker-compose.yml maps the HTTP port to :8076 and routes it
# through Traefik as well — while an entry in state.servers_list carries whatever
# src/proxmox.py and the merge put on it. Serialising that dict wholesale means every
# field ever added to an entry lands on a public page the moment it appears; naming
# them here means it has to be put there on purpose.
#
# `host` IS published, deliberately: with several PVE hosts merged into one zone it is
# how a name served by two of them becomes visible to whoever is reading the page.
# `vmid` is not — it identifies a guest inside somebody's Proxmox and says nothing to
# a reader of a status page.
#
# The tuple is also the column ORDER of the HTML table below, so the two endpoints
# cannot drift apart: a field added here shows up on both or on neither.
PUBLISHED_FIELDS = ("domain", "host", "ipv4", "ipv6", "status")

# Column heading and empty-cell placeholder per published field.
FIELD_TITLES = {"domain": "Domain", "host": "Host", "ipv4": "IPv4", "ipv6": "IPv6",
                "status": "Status"}
FIELD_PLACEHOLDERS = {"ipv4": "--.--.--.--"}


def public_view(servers):
    """Project the zone onto PUBLISHED_FIELDS — what both `/` and `/json` are built from."""
    return [{field: server.get(field) for field in PUBLISHED_FIELDS} for server in servers]


class StatusRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            if self.path == "/":
                self.send_html_table_response(200, state.servers_list)
            elif self.path == "/json":
                self.send_json_response(200, public_view(state.servers_list))
            elif self.path == "/health":
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"ok")
            else:
                self.send_response(404)
                self.end_headers()
        except UnicodeDecodeError:
            self.log_error("[HTTP] Received malformed request with encoding issues")
            self.send_response(400)
            self.end_headers()
        except Exception as e:
            self.log_error("[HTTP] Internal server error: %s", str(e))
            self.send_response(500)
            self.end_headers()

    def send_json_response(self, status_code, data):
        self.send_response(status_code)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def send_html_table_response(self, status_code, data):
        self.send_response(status_code)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        # Built from the same PUBLISHED_FIELDS projection /json uses, in the same order:
        # the two views of the zone are then one decision rather than two lists that
        # have to be remembered separately. Host is among them because several PVE hosts
        # are merged into one zone, and this page is where a name served by two of them
        # is actually visible.
        # .get() and not [] on purpose: a field added to PUBLISHED_FIELDS without a
        # heading here shows up as its own field name, which is ugly. A KeyError would
        # make this page 500 instead — and `/` is what the compose healthcheck polls, so
        # the container would go unhealthy and the updater would roll the image back.
        table_header = "<tr>" + "".join(
            f"<th>{html.escape(FIELD_TITLES.get(field, field))}</th>"
            for field in PUBLISHED_FIELDS) + "</tr>"
        # Escaped, because every value here started life as a VM name on the PVE side —
        # this page has no business rendering whatever somebody called a guest as markup.
        table_rows = "".join(
            "<tr>" + "".join(
                "<td>{}</td>".format(html.escape(str(
                    server[field] if server[field] is not None
                    else FIELD_PLACEHOLDERS.get(field, "--"))))
                for field in PUBLISHED_FIELDS) + "</tr>"
            for server in public_view(data)
        )
        html_content = f"<html><body><table border='1'>{table_header}{table_rows}</table></body></html>"
        self.wfile.write(html_content.encode("utf-8"))

    def log_message(self, fmt, *args):
        logger.debug(f"{self.client_address[0]} - - [{self.log_date_time_string()}] {fmt % args}")


def start_http_server():
    server_address = ("", settings.http_port)
    httpd = ThreadingHTTPServer(server_address, StatusRequestHandler)
    logger.log(logging.CRITICAL, f"[HTTP] Server started on port {settings.http_port}...")
    httpd.serve_forever()
