import logging
import socket

import dns.flags
import dns.message
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from src import state
from src.logging_setup import logger
from src.settings import settings


def handle_dns_query(data, addr):
    request = dns.message.from_wire(data)
    qname = request.question[0].name.to_text()
    dns_name = qname.lower().strip(".")
    ttl = 1
    logger.info(f"[DNS] DNS query from {addr[0]} for '{dns_name}': ")

    for question in request.question:
        if question.rdtype == dns.rdatatype.PTR:
            reversed_ip = dns_name.rstrip(".").split(".in-addr.arpa")[0].split(".")
            if len(reversed_ip) == 4:
                ip_address = ".".join(reversed(reversed_ip))
            else:
                reversed_ip = dns_name.rstrip(".").split(".ip6.arpa")[0].split(".")
                ip_address = ":".join(reversed(reversed_ip))

            for srv in state.servers_list:
                if srv.get("ipv4") == ip_address or srv.get("ipv6") == ip_address:
                    logger.info(f"[DNS] Return PTR record: {srv['domain']}")
                    response = dns.message.make_response(request)
                    response.set_rcode(dns.rcode.NOERROR)
                    response.flags |= dns.flags.AA
                    rrset = dns.rrset.from_text(qname, ttl, dns.rdataclass.IN, dns.rdatatype.PTR, srv["domain"] + ".")
                    response.answer.append(rrset)
                    return response.to_wire()

        for server in state.servers_list:
            if dns_name == server["domain"] or (settings.subdomains and dns_name.endswith(f".{server['domain']}")):
                response = dns.message.make_response(request)
                response.set_rcode(dns.rcode.NOERROR)
                response.flags |= dns.flags.AA

                if question.rdtype == dns.rdatatype.A and "ipv4" in server:
                    logger.info(f"[DNS] Return A record: {server['ipv4']}")
                    rrset = dns.rrset.from_text(qname, ttl, dns.rdataclass.IN, dns.rdatatype.A, server["ipv4"])
                    response.answer.append(rrset)
                elif question.rdtype == dns.rdatatype.AAAA and "ipv6" in server:
                    logger.info(f"[DNS] Return AAAA record: {server['ipv6']}")
                    rrset = dns.rrset.from_text(qname, ttl, dns.rdataclass.IN, dns.rdatatype.AAAA, server["ipv6"])
                    response.answer.append(rrset)

                return response.to_wire()

    response = dns.message.make_response(request)
    response.set_rcode(dns.rcode.NXDOMAIN)
    logger.info("[DNS] Return NXDOMAIN")
    return response.to_wire()


def start_dns_server():
    address = "0.0.0.0"
    port = settings.dns_port
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((address, port))

    logger.log(logging.CRITICAL, f"[DNS] Server run on port {port}/udp on {address}...")

    while True:
        try:
            data, addr = sock.recvfrom(512)
            response = handle_dns_query(data, addr)
            sock.sendto(response, addr)
        except Exception as e:
            logger.error(f"[DNS] Error handling request: {e}")
