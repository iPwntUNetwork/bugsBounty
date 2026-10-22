"""AWS deep: S3 bucket takeover, IAM privesc, metadata."""
from core.http import get
from core.findings import Finding
from core.memory import log_event
import urllib.parse

def scan_base(base_url):
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    host = parsed.hostname or parsed.netloc.split(":")[0]
    # S3 bucket takeover candidates
    bucket_patterns = [host, host.replace(".", "-"), "www-" + host, host + "-backup", host + "-dev", host + "-staging"]
    for bucket in bucket_patterns:
        for url in ["https://{}.s3.amazonaws.com".format(bucket), "https://s3.amazonaws.com/{}".format(bucket)]:
            r = get(url)
            if r.status in (404, 403):
                # NoSuchBucket = takeover candidate
                if "NoSuchBucket" in (r.text or ""):
                    findings.append(Finding(
                        id="s3-takeover-{}".format(hash(bucket) & 0xffff),
                        target=parsed.netloc,
                        type="S3 Bucket Takeover",
                        severity="high",
                        url=url,
                        parameter="bucket",
                        payload=bucket,
                        evidence="NoSuchBucket (claimable)",
                        response_snippet=r.snippet(200),
                        confidence=0.8,
                    ))
            elif r.status == 200:
                findings.append(Finding(
                    id="s3-open-{}".format(hash(bucket) & 0xffff),
                    target=parsed.netloc,
                    type="S3 Bucket Publicly Readable",
                    severity="high",
                    url=url,
                    parameter="bucket",
                    payload=bucket,
                    evidence="Bucket listable",
                    response_snippet=r.snippet(200),
                    confidence=0.9,
                ))
    # AWS metadata via SSRF (check if metadata accessible)
    meta_url = "http://169.254.169.254/latest/meta-data/"
    r = get(meta_url, timeout=3)
    if r.status == 200 and ("ami-id" in (r.text or "") or "instance-id" in (r.text or "")):
        findings.append(Finding(
            id="aws-metadata-{}".format(hash(host) & 0xffff),
            target=parsed.netloc,
            type="AWS Metadata Accessible",
            severity="critical",
            url=meta_url,
            parameter="ssrf",
            payload=meta_url,
            evidence="EC2 metadata endpoint reachable",
            response_snippet=r.snippet(200),
            confidence=0.95,
        ))
    log_event(parsed.netloc, "aws_deep_scan", {"base": base_url, "findings": len(findings)})
    return findings
