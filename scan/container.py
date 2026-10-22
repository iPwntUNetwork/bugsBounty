"""Container/Kubernetes exposure: Docker API, K8s dashboard, etcd, kubelet."""
from core.http import get
from core.findings import Finding
from core.memory import log_event
import urllib.parse

CONTAINER_PATHS = [
    ("/v1.24/containers/json", "Docker API", 2375),
    ("/containers/json", "Docker API", 2375),
    ("/api/v1/namespaces", "Kubernetes API", 6443),
    ("/api/v1/pods", "Kubernetes API", 6443),
    ("/healthz", "Kubelet", 10250),
    ("/metrics", "Kubelet metrics", 10250),
    ("/pods", "Kubelet pods", 10250),
    ("/v2/keys", "etcd", 2379),
    ("/version", "Kubernetes", 8080),
]

def scan_base(base_url):
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    host = parsed.hostname or parsed.netloc.split(":")[0]
    for path, name, port in CONTAINER_PATHS:
        for scheme in ["http", "https"]:
            url = "{}://{}:{}{}".format(scheme, host, port, path)
            r = get(url, timeout=5)
            if r.status == 0:
                continue
            text = (r.text or "").lower()
            if r.status == 200 and any(k in text for k in ["containers", "namespaces", "pods", "etcd", "docker", "kubelet", "cluster"]):
                findings.append(Finding(
                    id="container-{}-{}".format(name.replace(" ", ""), hash(url) & 0xffff),
                    target=parsed.netloc,
                    type="{} Exposed".format(name),
                    severity="critical",
                    url=url,
                    parameter="port",
                    payload="{}:{}".format(host, port),
                    evidence="Container orchestration API accessible",
                    response_snippet=r.snippet(200),
                    confidence=0.8,
                ))
    log_event(parsed.netloc, "container_scan", {"base": base_url, "findings": len(findings)})
    return findings
