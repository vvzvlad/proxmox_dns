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

config = json.loads(os.environ.get('JSON_CONFIG'))

# Disabling SSL warnings for self-signed certificates
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

servers_list = []

def get_vm_network_and_hostname(proxmox_server, node, vmid, cookies, headers):
    network_interfaces_url = f'https://{proxmox_server}:8006/api2/json/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces'
    hostname_url = f'https://{proxmox_server}:8006/api2/json/nodes/{node}/qemu/{vmid}/agent/get-host-name'

    network_response = requests.get(network_interfaces_url, cookies=cookies, headers=headers, verify=False)
    hostname_response = requests.get(hostname_url, cookies=cookies, headers=headers, verify=False)

    if network_response.status_code == 200 and hostname_response.status_code == 200:
        network_data = network_response.json()['data']
        hostname_data = hostname_response.json()['data']['result']['host-name']
        domain = hostname_data.split('-', 1)[0]+'.lc'
        ip_addresses = [ip['ip-address'] for iface in network_data['result'] for ip in iface.get('ip-addresses', []) if ip['ip-address-type'] == 'ipv4' and ip['ip-address'].startswith('10.31.')]
        return hostname_data, ip_addresses, domain
    else:
        return "None", "0.0.0.0", "None"

def fetch_proxmox_servers(proxmox_server, username, password, node):
    global servers_list
    auth_url = f'https://{proxmox_server}:8006/api2/json/access/ticket'
    auth_data = {
        'username': username,
        'password': password
    }

    try:
        auth_response = requests.post(auth_url, data=auth_data, verify=False)
        if auth_response.status_code == 200:
            auth_response_json = auth_response.json()
            csrf_token = auth_response_json['data']['CSRFPreventionToken']
            ticket = auth_response_json['data']['ticket']
            
            cookies = {'PVEAuthCookie': ticket}
            headers = {
                'CSRFPreventionToken': csrf_token,
                'Accept': 'application/json',
            }
                
            list_vms_url = f'https://{proxmox_server}:8006/api2/json/nodes/{node}/qemu'
            print(f"[Proxmox] Update server list on node {node}..")
            response = requests.get(list_vms_url, cookies=cookies, headers=headers, verify=False)
            
            if response.status_code == 200:
                vms = response.json()['data']   
                for vm in vms:
                    vmid = vm['vmid']
                    if not any(server['vmid'] == vmid for server in servers_list):
                        print(f"[Proxmox] Get hostname and IP addresses for VM {vmid}..")
                        hostname, ip_addresses, domain = get_vm_network_and_hostname(proxmox_server, node, vmid, cookies, headers)
                        if hostname and ip_addresses:
                            server_info = {
                                "name": vm['name'],
                                "vmid": vmid,
                                "hostname": hostname,
                                "domain": domain,
                                "ip": ip_addresses[0] if ip_addresses else ""
                            }
                            servers_list.append(server_info)
            else:
                print("[Proxmox] Error fetching VM list:", response.text)
        else:
            print("[Proxmox] Authentication error:", auth_response.text)
    except Exception as e:
        print(f"[Proxmox] An error occurred: {e}")
        traceback.print_exc()


def update_servers_periodically():
    while True:
        for server in config:
            fetch_proxmox_servers(server['address'], server['username'], server['password'], server['node'])
            time.sleep(10)     

def handle_dns_query(data, addr):
    request = dns.message.from_wire(data)
    qname = request.question[0].name.to_text()
    print(f"[DNS-Server] DNS query for {qname} from {addr}")

    if not qname.endswith('.'):
        qname += '.'

    for server in servers_list:
        if server['domain']+"." == qname or (server['name']+".lc.") == qname:
            ip_address = server['ip']
            print(f"[DNS-Server] return {ip_address}")
            response = dns.message.make_response(request)
            response.set_rcode(dns.rcode.NOERROR)
            rrset = dns.rrset.from_text(qname, 3600, dns.rdataclass.IN, dns.rdatatype.A, ip_address)
            response.answer.append(rrset)
            return response.to_wire()

    response = dns.message.make_response(request)
    response.set_rcode(dns.rcode.NXDOMAIN)
    print(f"[DNS-Server] No server found for {qname}, return NXDOMAIN")
    return response.to_wire()


def start_dns_server(port=5354):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ('0.0.0.0', port)
    sock.bind(server_address)

    print(f"Proxmox and MDNS DNS proxy run on port {port}...")

    while True:
        data, addr = sock.recvfrom(512) 
        response = handle_dns_query(data, addr)
        sock.sendto(response, addr)



class mdns_listener:
    def remove_service(self, zeroconf, type, name):
        global servers_list
        print(f"[MDNS] Service {name} removed")
        # Assuming the service name corresponds to the hostname or domain of the server
        servers_list = [server for server in servers_list if server['hostname'] != name and server['name'] != name]

    def add_service(self, zeroconf, type, name):
        global servers_list
        info = zeroconf.get_service_info(type, name)
        print(f"[MDNS] Service {name} discovered at {info.server}:{info.port}, addresses {info.parsed_addresses()}")
        # Add the server if it's not already in the list
        if not any(server['hostname'] == name or server['name'] == name for server in servers_list):
            ip_addresses = info.parsed_addresses()
            if ip_addresses:
                server_info = {
                    "name": name,
                    "hostname": name,  # Assuming the hostname and service name are the same
                    "domain": name.split('.')[0] + '.lc',  # Example of creating domain from name
                    "ip": ip_addresses[0],  # Taking the first IP address
                    "vmid": "000",
                }
                servers_list.append(server_info)

    def update_service(self, zeroconf, type, name):
        global servers_list
        info = zeroconf.get_service_info(type, name)
        print(f"[MDNS] Service {name} updated at {info.server}:{info.port}, addresses {info.parsed_addresses()}")
        # Update the server info if it exists in the list
        for server in servers_list:
            if server['hostname'] == name or server['name'] == name:
                ip_addresses = info.parsed_addresses()
                if ip_addresses:
                    server['domain'] = name.split('.')[0] + '.lc'  # Update domain
                    server['ip'] = ip_addresses[0]  # Update IP address
                break  # Exit the loop once the server is found and updated


def monitor_mdns():
    zeroconf = Zeroconf()
    listener = mdns_listener()
    browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
    try:
        while True:
            time.sleep(0.1)
    finally:
        zeroconf.close()

def broadcast_update():
    multicast_group = '224.0.0.251'
    server_address = ('', 5355) 

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(server_address)
    group = socket.inet_aton(multicast_group)
    mreq = struct.pack('4sL', group, socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    try:
        while True:
            data, address = sock.recvfrom(1024)
            if data.decode().strip() == "UPDATEEE":
                print(f"[BROADCAST] Run update..")
                for server in config:
                    fetch_proxmox_servers(server['address'], server['username'], server['password'], server['node'])
                print(f"[BROADCAST] End update..")
    finally:
        sock.close()

update_thread = threading.Thread(target=update_servers_periodically, daemon=True)
update_thread.start()

dns_thread = threading.Thread(target=start_dns_server, daemon=True)
dns_thread.start()

mdns_thread = threading.Thread(target=monitor_mdns, daemon=True)
mdns_thread.start()

broadcast_update_thread = threading.Thread(target=broadcast_update, daemon=True)
broadcast_update_thread.start()

time.sleep(10)
print(json.dumps(servers_list, indent=4))

while True:
    time.sleep(60)
    print(json.dumps(servers_list, indent=4))
