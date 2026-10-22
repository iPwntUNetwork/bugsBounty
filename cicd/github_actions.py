"""GitHub Actions security: injection, secret exfil, runner poisoning."""
from core.http import get
from core.findings import Finding
from core.memory import log_event
import urllib.parse, re

def scan_repo(repo_url):
    findings = []
    parsed = urllib.parse.urlparse(repo_url)
    # Check for workflow files
    for path in ["/.github/workflows", "/actions", "/.github/workflows/ci.yml", "/.github/workflows/main.yml"]:
        url = "{}://{}{}".format(parsed.scheme, parsed.netloc, path)
        r = get(url)
        if r.status == 200:
            findings.append(Finding(
                id="gha-workflow-{}-{}".format(path.strip("/").replace("/", "-"), hash(url) & 0xffff),
                target=parsed.netloc,
                type="GitHub Actions Workflow Exposed",
                severity="info",
                url=url,
                parameter="path",
                payload=path,
                evidence="Workflow file accessible",
                response_snippet=r.snippet(200),
                confidence=0.7,
            ))
            # check for injection patterns
            text = r.text or ""
            if "${{" in text and "github.event" in text:
                findings.append(Finding(
                    id="gha-injection-{}".format(hash(url) & 0xffff),
                    target=parsed.netloc,
                    type="GitHub Actions Injection (potential)",
                    severity="high",
                    url=url,
                    parameter="workflow",
                    payload="${{ github.event... }}",
                    evidence="Untrusted input in workflow",
                    response_snippet=text[:300],
                    confidence=0.6,
                ))
    log_event(parsed.netloc, "cicd_scan", {"repo": repo_url, "findings": len(findings)})
    return findings
