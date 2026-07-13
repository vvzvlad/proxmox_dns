import ipaddress
import logging
import socket

import dns.exception
import dns.flags
import dns.message
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.reversename
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
            # Convert the reverse-map name (in-addr.arpa / ip6.arpa) back to an IP.
            # dnspython handles both IPv4 and IPv6 correctly; the previous manual
            # nibble joining produced invalid IPv6 addresses that never matched.
            try:
                query_ip = ipaddress.ip_address(dns.reversename.to_address(question.name))
            except (dns.exception.DNSException, ValueError):
                query_ip = None

            # The unspecified address (0.0.0.0 / ::) is the sentinel stored for
            # stopped or agent-less VMs; a PTR query for it must not match them.
            if query_ip is not None and query_ip.is_unspecified:
                query_ip = None

            if query_ip is not None:
                for srv in state.servers_list:
                    # Match against the field of the right family; compare parsed IP
                    # objects so compressed and exploded IPv6 forms are treated equal.
                    srv_ip = srv.get("ipv4") if query_ip.version == 4 else srv.get("ipv6")
                    if not srv_ip:
                        continue
                    try:
                        if ipaddress.ip_address(srv_ip) == query_ip:
                            logger.info(f"[DNS] Return PTR record: {srv['domain']}")
                            response = dns.message.make_response(request)
                            response.set_rcode(dns.rcode.NOERROR)
                            response.flags |= dns.flags.AA
                            rrset = dns.rrset.from_text(qname, ttl, dns.rdataclass.IN, dns.rdatatype.PTR, srv["domain"] + ".")
                            response.answer.append(rrset)
                            return response.to_wire()
                    except ValueError:
                        continue

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
