"""GraphQL audit scanner."""
from core.http import get, post
from core.findings import Finding
from core.memory import log_event
import urllib.parse, json

INTROSPECTION_QUERY = {"query": "{ __schema { queryType { name } types { name fields { name } } } }"}

def find_endpoints(base_url):
    parsed = urllib.parse.urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    cands = ["/graphql", "/graphiql", "/api/graphql", "/v1/graphql", "/query", "/gql", "/graphql/console"]
    found = []
    for c in cands:
        url = root + c
        r = get(url)
        if r.status in (200, 400, 405):
            found.append(url)
    return found

def scan_endpoint(url):
    findings = []
    # introspection
    r = post(url, json=INTROSPECTION_QUERY, headers={"Content-Type": "application/json"})
    if r.status == 200 and "__schema" in (r.text or ""):
        findings.append(Finding(
            id=f"gql-intro-{hash(url) & 0xffff:x}",
            target=urllib.parse.urlparse(url).netloc,
            type="GraphQL Introspection Enabled",
            severity="medium",
            url=url,
            parameter="query",
            payload="introspection",
            evidence="Schema returned via introspection",
            response_snippet=r.snippet(200),
            confidence=0.95,
        ))
    # batching DoS test (small)
    batch = [{"query": "{__typename}"} for _ in range(10)]
    r = post(url, json=batch, headers={"Content-Type": "application/json"})
    if r.status == 200 and isinstance(r.text, str) and r.text.count("__typename") >= 5:
        findings.append(Finding(
            id=f"gql-batch-{hash(url) & 0xffff:x}",
            target=urllib.parse.urlparse(url).netloc,
            type="GraphQL Batching Allowed",
            severity="low",
            url=url,
            parameter="body",
            payload="batched queries",
            evidence="Batched query accepted",
            response_snippet=r.snippet(200),
            confidence=0.7,
        ))
    # field suggestion
    r = post(url, json={"query": "{ __typo }"}, headers={"Content-Type": "application/json"})
    if r.status == 200 and ("Did you mean" in (r.text or "") or "suggestion" in (r.text or "").lower()):
        findings.append(Finding(
            id=f"gql-suggest-{hash(url) & 0xffff:x}",
            target=urllib.parse.urlparse(url).netloc,
            type="GraphQL Field Suggestions Enabled",
            severity="info",
            url=url,
            parameter="query",
            payload="{ __typo }",
            evidence="Field suggestions leak schema",
            response_snippet=r.snippet(200),
            confidence=0.8,
        ))
    log_event(urllib.parse.urlparse(url).netloc, "graphql_scan", {"url": url, "findings": len(findings)})
    return findings

def scan_base(base_url):
    findings = []
    for ep in find_endpoints(base_url):
        findings.extend(scan_endpoint(ep))
    return findings
