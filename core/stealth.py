"""Stealth browser profiles, rotating User-Agents, 429/403 burn tracking, and origin spoofing headers."""
import os
import random
import threading
import time

_STEALTH_LOCK = threading.RLock()
_BURNED_UAS: dict[str, set[str]] = {}
_HOST_CUR_IDX: dict[str, int] = {}

BROWSER_PROFILES = [
    {
        "name": "chrome131_win11",
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "headers": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Sec-Ch-Ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
        },
    },
    {
        "name": "firefox133_mac",
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:133.0) Gecko/20100101 Firefox/133.0",
        "headers": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-AU,en-US;q=0.8,en;q=0.6",
            "Upgrade-Insecure-Requests": "1",
        },
    },
    {
        "name": "safari18_mac",
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
        "headers": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-AU,en;q=0.9",
        },
    },
    {
        "name": "edge131_win11",
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
        "headers": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-GB,en;q=0.9",
            "Sec-Ch-Ua": '"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
            "Sec-Ch-Ua-Platform": '"Windows"',
        },
    },
    {
        "name": "chrome131_linux",
        "ua": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "headers": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.8",
            "Sec-Ch-Ua-Platform": '"Linux"',
        },
    },
    {
        "name": "mobile_ios18_safari",
        "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
        "headers": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-AU,en-US;q=0.9",
        },
    },
]

USER_AGENTS = [p["ua"] for p in BROWSER_PROFILES]

ORIGIN_SPOOF_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"},
    {"X-Forwarded-For": "10.0.0.1", "X-Originating-IP": "10.0.0.1"},
    {"X-Forwarded-For": "172.16.0.1", "Client-IP": "172.16.0.1"},
    {"True-Client-IP": "127.0.0.1", "CF-Connecting-IP": "127.0.0.1"},
]


def _norm_host(host_or_url: str) -> str:
    if "://" in (host_or_url or ""):
        import urllib.parse
        return urllib.parse.urlparse(host_or_url).netloc or host_or_url
    return host_or_url or "global"


def select_browser_profile(host: str = "global", force_rotate: bool = False) -> dict:
    host = _norm_host(host)
    with _STEALTH_LOCK:
        burned = _BURNED_UAS.setdefault(host, set())
        idx = _HOST_CUR_IDX.get(host, random.randrange(len(BROWSER_PROFILES)))
        if force_rotate:
            idx = (idx + 1) % len(BROWSER_PROFILES)
        for offset in range(len(BROWSER_PROFILES)):
            cand = BROWSER_PROFILES[(idx + offset) % len(BROWSER_PROFILES)]
            if cand["ua"] not in burned:
                _HOST_CUR_IDX[host] = (idx + offset) % len(BROWSER_PROFILES)
                return cand
        burned.clear()
        _HOST_CUR_IDX[host] = idx
        return BROWSER_PROFILES[idx]


def pick_ua(host: str = "global") -> str:
    return select_browser_profile(host)["ua"]


def burn_ua(host: str, ua: str):
    if not ua:
        return
    host = _norm_host(host)
    with _STEALTH_LOCK:
        _BURNED_UAS.setdefault(host, set()).add(ua)
        _HOST_CUR_IDX[host] = (_HOST_CUR_IDX.get(host, 0) + 1) % len(BROWSER_PROFILES)


def random_ua() -> str:
    return random.choice(USER_AGENTS)


def stealth_delay():
    time.sleep(random.uniform(0.15, 0.55))


def get_proxy():
    return os.environ.get("BUGHUNTER_PROXY", None)
