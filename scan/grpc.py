"""gRPC service discovery and reflection."""
from core.http import get, post
from core.findings import Finding
from core.memory import log_event
import urllib.parse

def scan_base(base_url):
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    root = "{}://{}".format(parsed.scheme, parsed.netloc)
    # gRPC-web endpoints
    for path in ["/grpc", "/grpc-web", "/api/grpc", "/proto", "/reflection"]:
        url = root + path
        r = get(url)
        if r.status != 0 and r.status != 404:
            findings.append(Finding(
                id="grpc-{}-{}".format(path.strip("/"), hash(url) & 0xffff),
                target=parsed.netloc,
                type="gRPC Endpoint (potential)",
                severity="info",
                url=url,
                parameter="path",
                payload=path,
                evidence="Non-404 response (status {})".format(r.status),
                response_snippet=r.snippet(200),
                confidence=0.4,
            ))
    # gRPC reflection (grpc.reflection.v1alpha.ServerReflection)
    r = post(root, data="", headers={"Content-Type": "application/grpc", "TE": "trailers"})
    if r.status != 0 and r.status != 404:
        findings.append(Finding(
            id="grpc-reflection-{}".format(hash(base_url) & 0xffff),
            target=parsed.netloc,
            type="gRPC Reflection Enabled",
            severity="medium",
            url=root,
            parameter="grpc",
            payload="ServerReflection",
            evidence="gRPC server responded (status {})".format(r.status),
            response_snippet=r.snippet(200),
            confidence=0.5,
        ))
    log_event(parsed.netloc, "grpc_scan", {"base": base_url, "findings": len(findings)})
    return findings

scan_url = scan_base
