import requests
import threading
import time
import dns.resolver
import dns.message
import dns.query
import socket
import os
import sys
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
                
                svrlist = [  { "domain": server['domain'],  "ipv4": server.get('ipv4'),   "ipv6": server.get('ipv6')   } 
                    for server in servers_list
                ]
                
                self.wfile.write(json.dumps(svrlist).encode('utf-8'))
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

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - - [%s] %s\n" % (self.client_address[0], self.log_date_time_string(), fmt % args))

def start_http_server():
    server_address = ('', 80) 
    httpd = ThreadingHTTPServer(server_address, SimpleHTTPRequestHandler)
    raw_print("[HTTP] Server started on port 80...", flush=True)
    httpd.serve_forever()

def handle_dns_query(data, addr):
    request = dns.message.from_wire(data)
    qname = request.question[0].name.to_text()
    dns_name = qname.lower().strip(".")
    ttl = 1
    print(f"[DNS] DNS query from {addr[0]} for '{dns_name}': ", end='', flush=True)

    for server in servers_list:
        if dns_name == server['domain'] or (subdomains is not None and dns_name.endswith(f".{server['domain']}")):
            response = dns.message.make_response(request)
            response.set_rcode(dns.rcode.NOERROR)
            response.flags |= dns.flags.AA # Authoritative Answer

            for question in request.question:
                if question.rdtype == dns.rdatatype.A and 'ipv4' in server:
                    print(f"Return A record: {server['ipv4']}", flush=True)
                    rrset = dns.rrset.from_text(qname, ttl, dns.rdataclass.IN, dns.rdatatype.A, server['ipv4'])
                    response.answer.append(rrset)
                elif question.rdtype == dns.rdatatype.AAAA and 'ipv6' in server:
                    print(f"Return AAAA record: {server['ipv6']}", flush=True)
                    rrset = dns.rrset.from_text(qname, ttl, dns.rdataclass.IN, dns.rdatatype.AAAA, server['ipv6'])
                    response.answer.append(rrset)

            return response.to_wire()

    response = dns.message.make_response(request)
    response.set_rcode(dns.rcode.NXDOMAIN)
    print(f"Return NXDOMAIN", flush=True)
    return response.to_wire()


def start_dns_server(port=53, address='0.0.0.0'):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (address, port)
    sock.bind(server_address)

    raw_print(f"[DNS] Server run on port {port}/udp on {address}...", flush=True)

    while True:
        data, addr = sock.recvfrom(512) 
        response = handle_dns_query(data, addr)
        sock.sendto(response, addr)

def get_vm_ip(proxmox, node, vm):
    domain = (vm['name'].split('-')[0]+".lc").lower()
    def_ip_v4 = "00.00.00.00"
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
        print(f"[Proxmox] Failed to connect to api: {e}", flush=True)
        return None 
    
    for node in nodes:
        try:
            vms = proxmox.nodes(node['node']).qemu.get()
            for vm in vms:
                if vm.get('template', 0) == 1: 
                    continue
                
                vm_info = get_vm_ip(proxmox, node, vm)
                domains.append(vm_info)
                
                print(f"[Proxmox] Got IPv4 {vm_info['ipv4']} and IPv6 {vm_info['ipv6']} for domain {vm_info['domain']}", flush=True)
        
        except Exception as e:
            print(f"[Proxmox] Failed to retrieve VM list for node {node['node']}: {e}", flush=True)
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
            print(f"[Proxmox] Failed to update DNS servers list, left previous list", flush=True)
            continue
        servers_list.clear()
        servers_list.extend(domains)
        print(f"[Proxmox] Updated DNS servers list with {len(domains)} servers(period {sleep_delay})", flush=True)

        if len(domains) != previous_count: last_change_time = time.time()
        previous_count = len(domains)

        if last_change_time and time.time() - last_change_time < 60: sleep_delay = sleep_max
        else: sleep_delay = sleep_low

        
        


def main():
    servers_list.extend(get_domains())

    update_dns_thread = threading.Thread(target=update_dns_periodically, daemon=True)
    update_dns_thread.start()

    dns_serve_thread = threading.Thread(target=start_dns_server, daemon=True)
    dns_serve_thread.start()

    http_serve_thread = threading.Thread(target=start_http_server, daemon=True)
    http_serve_thread.start()

    raw_print(f"ProxDNS server started", flush=True)

    while True:
        time.sleep(30)
        max_domain_length = max(len(server['domain']) for server in servers_list)
        max_ipv4_length = max(len(server.get('ipv4', '')) for server in servers_list)
        max_ipv6_length = max(len(server.get('ipv6', '')) for server in servers_list)
        for server in servers_list:
            domain = server['domain'].ljust(max_domain_length)
            ipv4_address = server.get('ipv4', '--.--.--.--').ljust(max_ipv4_length)
            ipv6_address = server.get('ipv6', '--').ljust(max_ipv6_length)

            print(f"{domain}\t{ipv4_address}\t{ipv6_address}", flush=True)


if __name__ == "__main__":
    main()