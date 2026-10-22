"""Advanced DNS recon: zone transfer, reverse DNS, ASN."""
from core.memory import log_event
import socket

def zone_transfer(domain, ns=None):
    """Attempt DNS zone transfer (AXFR)."""
    results = []
    try:
        import dns.resolver, dns.zone, dns.query
        if ns is None:
            answers = dns.resolver.resolve(domain, 'NS')
            ns = str(answers[0])
        zone = dns.zone.from_xfr(dns.query.xfr(ns, domain))
        for name, node in zone.nodes.items():
            results.append(str(name) + "." + domain)
    except Exception:
        pass
    log_event(domain, "zone_transfer", {"count": len(results)})
    return results

def reverse_dns(ip):
    """Reverse DNS lookup."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

def asn_lookup(ip):
    """ASN lookup via Team Cymru."""
    try:
        import socket
        # Use DNS-based ASN lookup
        reversed_ip = ".".join(reversed(ip.split(".")))
        query = reversed_ip + ".origin.asn.cymru.com"
        answers = socket.gethostbyname_ex(query)
        return answers[2]
    except Exception:
        return None

def enumerate_ips(domain):
    """Resolve domain to IPs."""
    ips = set()
    try:
        for info in socket.getaddrinfo(domain, None):
            ips.add(info[4][0])
    except Exception:
        pass
    return list(ips)
