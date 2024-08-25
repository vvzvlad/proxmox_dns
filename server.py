import json
import logging
import os
import socket
import sys
import threading
import time

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from colorama import Fore, Style, init
import dns.message
import dns.query
import dns.resolver
import requests
from proxmoxer import ProxmoxAPI
from proxmoxer.core import ResourceException
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
servers_list = []

logging_level = os.environ.get('LOGGING')
subdomains = os.environ.get('SUBDOMAINS')

proxmox = ProxmoxAPI(os.environ.get('HOST'),
                    user=os.environ.get('USER'),
                    password=os.environ.get('PASSWORD'),
                    verify_ssl=False, service='PVE')

init(autoreset=True)

class ColoredFormatter(logging.Formatter):
    def format(self, record):
        if record.levelno == logging.ERROR:
            record.msg = f"{Fore.RED}{record.msg}{Style.RESET_ALL}"
        elif record.levelno == logging.WARNING:
            record.msg = f"{Fore.YELLOW}{record.msg}{Style.RESET_ALL}"
        elif record.levelno == logging.INFO:
            record.msg = f"{Fore.GREEN}{record.msg}{Style.RESET_ALL}"
        return super().format(record)

def setup_logger():
    logger_t = logging.getLogger("mdns_proxy")
    level = logging.getLevelName(logging_level.upper()) if logging_level else logging.INFO
    logger_t.setLevel(level)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    colored_formatter = ColoredFormatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(colored_formatter)
    logger_t.addHandler(console_handler)
    return logger_t

logger = setup_logger()

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            if self.path == '/':
                self._send_html_table_response(200, servers_list)
            else:
                self._send_response(404)
        except UnicodeDecodeError:
            self.log_error("[HTTP] Received malformed request with encoding issues")
            self._send_response(400)
        except Exception as e:
            self.log_error("[HTTP] Internal server error: %s", str(e))
            self._send_response(500)

    def _send_html_table_response(self, status_code, data):
        self.send_response(status_code)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        table_header = "<tr><th>Domain</th><th>IPv4</th><th>IPv6</th></tr>"
        table_rows = "".join(
            f"<tr><td>{server['domain']}</td><td>{server.get('ipv4', '--.--.--.--')}</td><td>{server.get('ipv6', '--')}</td></tr>"
            for server in data
        )
        html_content = f"<html><body><table border='1'>{table_header}{table_rows}</table></body></html>"
        self.wfile.write(html_content.encode('utf-8'))

    def _send_response(self, status_code):
        self.send_response(status_code)
        self.end_headers()

    def log_message(self, fmt, *args):
        logger.debug(f"{self.client_address[0]} - - [{self.log_date_time_string()}] {fmt % args}")

def start_http_server():
    server_address = ('', 80) 
    httpd = ThreadingHTTPServer(server_address, SimpleHTTPRequestHandler)
    logger.log(logging.CRITICAL, "[HTTP] Server started on port 80...")
    httpd.serve_forever()

def handle_dns_query(data, addr):
    request = dns.message.from_wire(data)
    qname = request.question[0].name.to_text()
    dns_name = qname.lower().strip(".")
    ttl = 1
    logger.info(f"[DNS] DNS query from {addr[0]} for '{dns_name}': ")

    for server in servers_list:
        if dns_name == server['domain'] or (subdomains is not None and dns_name.endswith(f".{server['domain']}")):
            response = dns.message.make_response(request)
            response.set_rcode(dns.rcode.NOERROR)
            response.flags |= dns.flags.AA # Authoritative Answer

            for question in request.question:
                if question.rdtype == dns.rdatatype.A and 'ipv4' in server:
                    logger.info(f"[DNS] Return A record: {server['ipv4']}")
                    rrset = dns.rrset.from_text(qname, ttl, dns.rdataclass.IN, dns.rdatatype.A, server['ipv4'])
                    response.answer.append(rrset)
                elif question.rdtype == dns.rdatatype.AAAA and 'ipv6' in server:
                    logger.info(f"[DNS] Return AAAA record: {server['ipv6']}")
                    rrset = dns.rrset.from_text(qname, ttl, dns.rdataclass.IN, dns.rdatatype.AAAA, server['ipv6'])
                    response.answer.append(rrset)
                elif question.rdtype == dns.rdatatype.PTR:
                    for srv in servers_list:
                        if srv.get('ipv4') == dns_name or srv.get('ipv6') == dns_name:
                            logger.info(f"[DNS] Return PTR record: {srv['domain']}")
                            rrset = dns.rrset.from_text(qname, ttl, dns.rdataclass.IN, dns.rdatatype.PTR, srv['domain'])
                            response.answer.append(rrset)
                            break

            return response.to_wire()

    response = dns.message.make_response(request)
    response.set_rcode(dns.rcode.NXDOMAIN)
    logger.info(f"[DNS] Return NXDOMAIN")
    return response.to_wire()


def start_dns_server(port=53, address='0.0.0.0'):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (address, port)
    sock.bind(server_address)

    logger.log(logging.CRITICAL, f"[DNS] Server run on port {port}/udp on {address}...")

    while True:
        try:
            data, addr = sock.recvfrom(512) 
            response = handle_dns_query(data, addr)
            sock.sendto(response, addr)
        except Exception as e:
            logger.error(f"[DNS] Error handling request: {e}")

def get_vm_ip(proxmox, node, vm):
    domain = (vm['name'].split('-')[0]+".lc").lower()
    def_ip_v4 = "0.0.0.0"
    def_ip_v6 = "::"
    try:
        vm_status = proxmox.nodes(node['node']).qemu(vm['vmid']).status.current.get()
        if vm_status['status'] != 'running':  return {"domain": domain, "ipv4": def_ip_v4, "ipv6": def_ip_v6}
        
        network_status = proxmox.nodes(node['node']).qemu(vm['vmid']).agent('network-get-interfaces').get()
        vm_ip_v4 = None
        vm_ip_v6 = None
        
        if 'result' in network_status:
            for interface in network_status['result']:
                if interface['name'].startswith(('lo', 'br-', 'veth', 'docker')):  continue
                for ip in interface.get('ip-addresses', []):
                    if ip['ip-address-type'] == 'ipv4' and not vm_ip_v4: vm_ip_v4 = ip['ip-address']
                    elif ip['ip-address-type'] == 'ipv6' and not vm_ip_v6: vm_ip_v6 = ip['ip-address']
                if vm_ip_v4 and vm_ip_v6:
                    break
        return { "domain": domain,  "ipv4": vm_ip_v4 or def_ip_v4,  "ipv6": vm_ip_v6 or def_ip_v6 }
    
    except ResourceException:
        return {"domain": domain, "ipv4": def_ip_v4, "ipv6": def_ip_v6}
    except Exception:
        return {"domain": domain, "ipv4": def_ip_v4, "ipv6": def_ip_v6}

def get_domains():
    domains = []
    try:
        nodes = proxmox.nodes.get()
    except requests.exceptions.ConnectionError as e:
        logger.error(f"[Proxmox] Failed to connect to api: {e}")
        return None 
    
    for node in nodes:
        try:
            vms = proxmox.nodes(node['node']).qemu.get()
            for vm in vms:
                if vm.get('template', 0) == 1: 
                    continue
                
                vm_info = get_vm_ip(proxmox, node, vm)
                domains.append(vm_info)
                
                logger.debug(f"[Proxmox] Got IPv4 {vm_info['ipv4']} and IPv6 {vm_info['ipv6']} for domain {vm_info['domain']}")
        
        except Exception as e:
            logger.error(f"[Proxmox] Failed to retrieve VM list for node {node['node']}: {e}")
            continue
    
    return domains


def update_dns_periodically():
    sleep_low = 1
    sleep_max = 5
    sleep_delay = sleep_max
    previous_count = 0
    last_change_time = None

    while True:
        time.sleep(sleep_delay)
        domains = get_domains()
        if domains is None: 
            logger.warning(f"[Proxmox] Failed to update DNS servers list, left previous list")
            continue
        servers_list.clear()
        servers_list.extend(domains)
        logger.info(f"[Proxmox] Updated DNS servers list with {len(domains)} servers(period {sleep_delay})")

        if len(domains) != previous_count: last_change_time = time.time()
        previous_count = len(domains)

        if last_change_time and time.time() - last_change_time < 60: sleep_delay = sleep_max
        else: sleep_delay = sleep_low

        
        


def main():
    servers_list.extend(get_domains())

    def start_thread(target):
        while True:
            try:
                target()
            except Exception as e:
                logger.error(f"[Thread] Error in {target.__name__}: {e}")
                time.sleep(1)

    threading.Thread(target=lambda: start_thread(update_dns_periodically), daemon=True).start()
    threading.Thread(target=lambda: start_thread(start_dns_server), daemon=True).start()
    threading.Thread(target=lambda: start_thread(start_http_server), daemon=True).start()

    logger.log(logging.CRITICAL, "ProxDNS server started")

    while True:
        time.sleep(30)
        max_domain_length = max(len(server['domain']) for server in servers_list)
        max_ipv4_length = max(len(server.get('ipv4', '')) for server in servers_list)
        max_ipv6_length = max(len(server.get('ipv6', '')) for server in servers_list)
        for server in servers_list:
            domain = server['domain'].ljust(max_domain_length)
            ipv4_address = server.get('ipv4', '--.--.--.--').ljust(max_ipv4_length)
            ipv6_address = server.get('ipv6', '--').ljust(max_ipv6_length)

            logger.debug(f"{domain}\t{ipv4_address}\t{ipv6_address}")


if __name__ == "__main__":
    main()
