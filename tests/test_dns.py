import dns.message
import dns.rcode
import dns.rdatatype

from src import state
from src.dns_server import handle_dns_query


def test_a_record_is_returned_for_known_domain(monkeypatch):
    monkeypatch.setattr(
        state,
        "servers_list",
        [{"domain": "foo.lc", "ipv4": "10.0.0.5", "ipv6": "fe80::1"}],
    )
    query = dns.message.make_query("foo.lc", dns.rdatatype.A)
    response = dns.message.from_wire(handle_dns_query(query.to_wire(), ("127.0.0.1", 5353)))
    assert response.rcode() == dns.rcode.NOERROR
    answers = [rr for rrset in response.answer for rr in rrset]
    assert any(str(rr) == "10.0.0.5" for rr in answers)


def test_unknown_domain_returns_nxdomain(monkeypatch):
    monkeypatch.setattr(state, "servers_list", [])
    query = dns.message.make_query("nope.lc", dns.rdatatype.A)
    response = dns.message.from_wire(handle_dns_query(query.to_wire(), ("127.0.0.1", 5353)))
    assert response.rcode() == dns.rcode.NXDOMAIN


def test_ptr_record_is_returned_for_known_ip(monkeypatch):
    monkeypatch.setattr(
        state,
        "servers_list",
        [{"domain": "foo.lc", "ipv4": "10.0.0.5", "ipv6": "fe80::1"}],
    )
    query = dns.message.make_query("5.0.0.10.in-addr.arpa", dns.rdatatype.PTR)
    response = dns.message.from_wire(handle_dns_query(query.to_wire(), ("127.0.0.1", 5353)))
    assert response.rcode() == dns.rcode.NOERROR
    answers = [rr for rrset in response.answer for rr in rrset]
    assert any("foo.lc" in str(rr) for rr in answers)
