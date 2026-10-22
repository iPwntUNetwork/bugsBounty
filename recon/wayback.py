"""Wayback Machine / archived URL discovery."""
from core.http import get
from core.memory import log_event
import json

def fetch_urls(domain):
    urls = set()
    try:
        r = get(f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey&limit=500", timeout=30)
        if r.status == 200 and r.text:
            data = json.loads(r.text)
            for row in data[1:]:
                if row:
                    urls.add(row[0])
    except Exception:
        pass
    log_event(domain, "wayback", {"count": len(urls)})
    return sorted(urls)
