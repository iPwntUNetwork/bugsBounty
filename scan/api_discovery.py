"""API discovery: OpenAPI/Swagger, API versioning, hidden endpoints."""
from core.http import get
from core.findings import Finding
from core.memory import log_event
import urllib.parse, json

API_PATHS = [
    "/swagger.json", "/swagger/v1/swagger.json", "/openapi.json", "/api-docs",
    "/v2/api-docs", "/v3/api-docs", "/swagger-ui.html", "/api/swagger",
    "/docs", "/redoc", "/api/v1", "/api/v2", "/api/v3", "/graphql",
    "/.well-known/openapi", "/swagger.yaml", "/openapi.yaml",
]

def scan_base(base_url):
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    root = "{}://{}".format(parsed.scheme, parsed.netloc)
    for path in API_PATHS:
        url = root + path
        r = get(url)
        if r.status == 0:
            continue
        if r.status == 200:
            text = (r.text or "").lower()
            if any(k in text for k in ["swagger", "openapi", "paths", "definitions", "components"]):
                findings.append(Finding(
                    id="api-{}-{}".format(path.strip("/").replace("/", "-"), hash(url) & 0xffff),
                    target=parsed.netloc,
                    type="API Schema Exposed",
                    severity="medium",
                    url=url,
                    parameter="path",
                    payload=path,
                    evidence="OpenAPI/Swagger schema accessible",
                    response_snippet=r.snippet(200),
                    confidence=0.9,
                ))
            # parse endpoints from schema
            try:
                data = json.loads(r.text)
                paths = data.get("paths", {})
                if paths:
                    findings.append(Finding(
                        id="api-endpoints-{}".format(hash(url) & 0xffff),
                        target=parsed.netloc,
                        type="API Endpoints Discovered",
                        severity="info",
                        url=url,
                        parameter="schema",
                        payload="{} endpoints".format(len(paths)),
                        evidence=", ".join(list(paths.keys())[:10]),
                        response_snippet=str(list(paths.keys())[:5]),
                        confidence=0.95,
                    ))
            except Exception:
                pass
    log_event(parsed.netloc, "api_discovery_scan", {"base": base_url, "findings": len(findings)})
    return findings
