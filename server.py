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
            print("Update server list..")
            response = requests.get(list_vms_url, cookies=cookies, headers=headers, verify=False)
            
            if response.status_code == 200:
                vms = response.json()['data']
                for vm in vms:
                    vmid = vm['vmid']
                    if not any(server['vmid'] == vmid for server in servers_list):
                        print(f"Get hostname and IP addresses for VM {vmid}..")
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
                print("Error fetching VM list:", response.text)
        else:
            print("Authentication error:", auth_response.text)
    except Exception as e:
        print(f"An error occurred: {e}")

def update_servers_periodically():
    while True:
        for server in config:
            fetch_proxmox_servers(server['address'], server['username'], server['password'], server['node'])
            time.sleep(10)     

def handle_dns_query(data, addr):
    request = dns.message.from_wire(data)
    qname = request.question[0].name.to_text()
    print(f"DNS query for {qname}")


    if not qname.endswith('.'):
        qname += '.'

    for server in servers_list:
        if server['domain']+"." == qname or (server['name']+".lc.") == qname:
            ip_address = server['ip']
            response = dns.message.make_response(request)
            response.set_rcode(dns.rcode.NOERROR)
            rrset = dns.rrset.from_text(qname, 3600, dns.rdataclass.IN, dns.rdatatype.A, ip_address)
            response.answer.append(rrset)
            return response.to_wire()

    response = dns.message.make_response(request)
    response.set_rcode(dns.rcode.NXDOMAIN)
    return response.to_wire()


def start_dns_server(port=5354):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ('0.0.0.0', port)
    sock.bind(server_address)

    print(f"proxmox2DNS proxy run on port {port}...")

    while True:
        data, addr = sock.recvfrom(512) 
        response = handle_dns_query(data, addr)
        sock.sendto(response, addr)



class mdns_listener:
    def remove_service(self, zeroconf, type, name):
        print(f"Сервис {name} удален")

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        print(f"Обнаружен сервис {name} на {info.server}:{info.port}, адреса {info.parsed_addresses()}")

def monitor_mdns():
    zeroconf = Zeroconf()
    listener = mdns_listener()
    browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
    try:
        while True:
            time.sleep(0.1)
    finally:
        zeroconf.close()




update_thread = threading.Thread(target=update_servers_periodically, daemon=True)
update_thread.start()

dns_thread = threading.Thread(target=start_dns_server, daemon=True)
dns_thread.start()

dns_thread = threading.Thread(target=monitor_mdns, daemon=True)
dns_thread.start()

while True:
    time.sleep(60)
    print(servers_list)