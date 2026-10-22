"""Database exposure: Redis, Mongo, Elasticsearch, Memcached."""
from core.http import get
from core.findings import Finding
from core.memory import log_event
import urllib.parse

DB_PATHS = [
    ("/", "redis", 6379),
]

def scan_base(base_url):
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    host = parsed.hostname or parsed.netloc.split(":")[0]
    # HTTP-based DB endpoints
    endpoints = {
        "redis": ["/", "/info"],
        "elasticsearch": ["/", "/_cluster/health", "/_cat/indices"],
        "mongodb": ["/", "/serverStatus"],
        "memcached": ["/"],
        "couchdb": ["/", "/_all_dbs"],
        "postgres": ["/"],
    }
    ports = {"redis": 6379, "elasticsearch": 9200, "mongodb": 27017, "memcached": 11211, "couchdb": 5984, "postgres": 5432}
    for db, paths in endpoints.items():
        for port in [ports[db], 80, 443]:
            for path in paths:
                for scheme in ["http", "https"]:
                    url = "{}://{}:{}{}".format(scheme, host, port, path)
                    r = get(url, timeout=5)
                    if r.status == 0:
                        continue
                    text = (r.text or "").lower()
                    indicators = {
                        "redis": ["redis_version", "redis_mode", "connected_clients"],
                        "elasticsearch": ["cluster_name", "elasticsearch", "number_of_nodes"],
                        "mongodb": ["mongodb", "ok", "version"],
                        "memcached": ["STAT", "memcached"],
                        "couchdb": ["couchdb", "welcome", "version"],
                    }
                    inds = indicators.get(db, [])
                    if any(i.lower() in text for i in inds):
                        findings.append(Finding(
                            id="db-{}-{}-{}".format(db, port, hash(url) & 0xffff),
                            target=parsed.netloc,
                            type="Database Exposed ({})".format(db),
                            severity="critical",
                            url=url,
                            parameter="port",
                            payload="{}:{}".format(host, port),
                            evidence="Database responds on HTTP port",
                            response_snippet=r.snippet(200),
                            confidence=0.8,
                        ))
    log_event(parsed.netloc, "db_exposure_scan", {"base": base_url, "findings": len(findings)})
    return findings
