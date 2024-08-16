import requests
import threading
import time
import dns.resolver
import dns.message
import dns.query
import socket
import os
import json
from zeroconf import ServiceBrowser, Zeroconf
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import traceback
import socket
import struct

from proxmoxer import ProxmoxAPI
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from proxmoxer.core import ResourceException  

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
servers_list = []

user = os.environ.get('USER')
password = os.environ.get('PASSWORD')
host = os.environ.get('HOST')
logging = os.environ.get('LOGGING')
subdomains = os.environ.get('SUBDOMAINS')
proxmox = ProxmoxAPI(host, user=user, password=password, verify_ssl=False, service='PVE')

raw_print = print
def print(*args, **kwargs):
    if logging is not None:
        raw_print(*args, **kwargs)

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            if self.path == '/':
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                svrlist = [{"domain": server['domain'], "ip": server['ip']} for server in servers_list]
                self.wfile.write(json.dumps(svrlist).encode('utf-8'))
            else:
                self.send_response(404)
                self.end_headers()
        except UnicodeDecodeError:
            print("Received malformed request with encoding issues", flush=True)
            self.send_response(400)
            self.end_headers()

    def log_message(self, fmt, *args):
        raw_print("%s - - [%s] %s\n" % (self.client_address[0],
                                        self.log_date_time_string(),
                                        fmt % args), flush=True)

def start_http_server():
    server_address = ('', 80) 
    httpd = ThreadingHTTPServer(server_address, SimpleHTTPRequestHandler)
    raw_print("HTTP server started on port 80...", flush=True)
    httpd.serve_forever()

def handle_dns_query(data, addr):
    request = dns.message.from_wire(data)
    qname = request.question[0].name.to_text()
    dns_name = qname.lower().strip(".")
    print(f"[DNS-Server] DNS query from {addr[0]} for '{dns_name}': ", end='', flush=True)

    for server in servers_list:
        if dns_name == server['domain'] or (subdomains is not None and dns_name.endswith(f".{server['domain']}")):
            print(f"Return {server['ip']}", flush=True)
            response = dns.message.make_response(request)
            response.set_rcode(dns.rcode.NOERROR)
            rrset = dns.rrset.from_text(qname, 0, dns.rdataclass.IN, dns.rdatatype.A, server['ip'])
            response.answer.append(rrset)
            return response.to_wire()

    response = dns.message.make_response(request)
    response.set_rcode(dns.rcode.NXDOMAIN)
    print(f"Return NXDOMAIN", flush=True)
    return response.to_wire()


def start_dns_server(port=53):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ('0.0.0.0', port)
    sock.bind(server_address)

    raw_print(f"DNS server run on port {port}...", flush=True)

    while True:
        data, addr = sock.recvfrom(512) 
        response = handle_dns_query(data, addr)
        sock.sendto(response, addr)

def update_dns():
    domains = []
    try:
        nodes = proxmox.nodes.get() 
    except requests.exceptions.ConnectionError as e:
        print(f"Failed to connect to Proxmox: {e}", flush=True)
        return None 

    for node in nodes:
        try:
            for vm in proxmox.nodes(node['node']).qemu.get():
                vm_status = proxmox.nodes(node['node']).qemu(vm['vmid']).status.current.get()
                if vm_status['status'] == 'running':
                    try:
                        network_status = proxmox.nodes(node['node']).qemu(vm['vmid']).agent('network-get-interfaces').get()
                        vm_ip = None
                        if 'result' in network_status:
                            for interface in network_status['result']:
                                if interface['name'] == 'lo': 
                                    continue
                                for ip in interface.get('ip-addresses', []):
                                    ip_address = ip['ip-address']
                                    if ip_address.count('.') == 3 and (ip_address.startswith('10.31.40') or ip_address.startswith('10.31.41')):
                                        vm_ip = ip_address
                                        break
                                if vm_ip:
                                    break
                        domain = vm['name'].split('-')[0]+".lc"
                        domains.append({ "domain": domain.lower(), "ip": vm_ip })
                    except ResourceException as e:
                        domain = vm['name'].split('-')[0]+".lc"
                        domains.append({ "domain": domain.lower(), "ip": "0.0.0.0" })
                        if "QEMU guest agent is not running" not in str(e) and "No QEMU guest agent configured" not in str(e):
                            print(f"Failed to get IP for VM {vm['name']}: {e}", flush=True)
                    except Exception as e:
                        domain = vm['name'].split('-')[0]+".lc"
                        domains.append({ "domain": domain.lower(), "ip": "0.0.0.0" })
                else:
                    domain = vm['name'].split('-')[0]+".lc"
                    domains.append({ "domain": domain.lower(), "ip": "0.0.0.0" })
        except Exception as e:
            print(f"Failed to retrieve VM list for node {node['node']}: {e}", flush=True)
            continue

    return domains


def update_servers_periodically():
    previous_count = 0
    last_change_time = None

    while True:
        domains = update_dns()
        if domains is None:
            time.sleep(2)
            continue
        servers_list.clear()
        servers_list.extend(domains)
        print(f"Updated DNS servers list with {len(domains)} servers", flush=True)

        if len(domains) != previous_count: last_change_time = time.time()
        if last_change_time and time.time() - last_change_time < 60:
            time.sleep(1)
        else:
            time.sleep(5)
        previous_count = len(domains)



update_thread = threading.Thread(target=update_servers_periodically, daemon=True)
update_thread.start()

dns_thread = threading.Thread(target=start_dns_server, daemon=True)
dns_thread.start()

http_thread = threading.Thread(target=start_http_server, daemon=True)
http_thread.start()

raw_print(f"Proxmox DNS server run", flush=True)

while True:
    time.sleep(30)
    formatted_list = ", ".join([f"{server['domain']}:{server['ip']}" for server in servers_list])
    print(f"Servers: {formatted_list}", flush=True)
