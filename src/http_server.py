import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from src import state
from src.logging_setup import logger
from src.settings import settings


class StatusRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            if self.path == "/":
                self.send_html_table_response(200, state.servers_list)
            elif self.path == "/json":
                self.send_json_response(200, state.servers_list)
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
        table_header = "<tr><th>Domain</th><th>IPv4</th><th>IPv6</th></tr>"
        table_rows = "".join(
            f"<tr><td>{server['domain']}</td><td>{server.get('ipv4', '--.--.--.--')}</td><td>{server.get('ipv6', '--')}</td></tr>"
            for server in data
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
