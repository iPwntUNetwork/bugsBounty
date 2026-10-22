"""Port scanning and service detection."""
from core.http import get
from core.findings import Finding
from core.memory import log_event
import socket, urllib.parse

COMMON_PORTS = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,8888,9200,27017]

def scan_host(host):
    findings = []
    open_ports = []
    for port in COMMON_PORTS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            if s.connect_ex((host, port)) == 0:
                open_ports.append(port)
            s.close()
        except Exception:
            pass
    if open_ports:
        findings.append(Finding(
            id="ports-{}".format(hash(host) & 0xffff),
            target=host,
            type="Open Ports",
            severity="info",
            url="http://{}".format(host),
            parameter="port",
            payload=",".join(str(p) for p in open_ports),
            evidence="Open ports: {}".format(open_ports),
            response_snippet="",
            confidence=0.99,
        ))
    log_event(host, "port_scan", {"host": host, "open": open_ports})
    return findings

def scan_base(base_url):
    parsed = urllib.parse.urlparse(base_url)
    host = parsed.hostname or parsed.netloc.split(":")[0]
    return scan_host(host)
