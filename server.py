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
import traceback
import socket
import struct

from proxmoxer import ProxmoxAPI
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from proxmoxer.core import ResourceException  

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


user = os.environ.get('USER')
password = os.environ.get('PASSWORD')
host = os.environ.get('HOST')
proxmox = ProxmoxAPI(host, user=user, password=password, verify_ssl=False, service='PVE')

servers_list = []
def handle_dns_query(data, addr):
    request = dns.message.from_wire(data)
    qname = request.question[0].name.to_text()
    dns_name = qname.lower().strip(".")
    print(f"[DNS-Server] DNS query from {addr[0]} for '{dns_name}': ", end='', flush=True)

    for server in servers_list:
        if dns_name == server['domain']:
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


def start_dns_server(port=5354):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ('0.0.0.0', port)
    sock.bind(server_address)

    print(f"Proxmox DNS proxy run on port {port}...", flush=True)

    while True:
        data, addr = sock.recvfrom(512) 
        response = handle_dns_query(data, addr)
        sock.sendto(response, addr)



def update_dns():
    domains = []
    for node in proxmox.nodes.get():
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
                    #print(f"VM Name: {vm['name']}, VM IP: {vm_ip}")
                    domain = vm['name'].split('-')[0]+".lc"
                    
                    server_info = { "domain": domain.lower(), "ip": vm_ip }
                    domains.append(server_info)
                except ResourceException as e:
                    if "QEMU guest agent is not running" not in str(e) and "No QEMU guest agent configured" not in str(e):
                        print(f"Failed to get IP for VM {vm['name']}: {e}", flush=True)
            #else:
            #    print(f"VM Name: {vm['name']} is not running, skipping.")
    return(domains)

def update_servers_periodically():
    while True:
        domains = update_dns()
        servers_list.clear()
        servers_list.extend(domains)
        print(f"Updated DNS servers list with {len(domains)} servers", flush=True)
        time.sleep(3)    


update_thread = threading.Thread(target=update_servers_periodically, daemon=True)
update_thread.start()

dns_thread = threading.Thread(target=start_dns_server, daemon=True)
dns_thread.start()

time.sleep(5)

while True:
    print(json.dumps(servers_list))
    time.sleep(600)
    
