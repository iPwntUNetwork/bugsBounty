"""Thread-safe mutexes and coordinated WAF payload failure/tamper tracker across worker threads."""
import threading
import time


class Mutex:
    def __init__(self):
        self._lock = threading.RLock()

    def __enter__(self):
        self._lock.acquire()
        return self

    def __exit__(self, *a):
        self._lock.release()


FINDINGS_LOCK = Mutex()
RATE_LOCK = Mutex()
MEMORY_LOCK = Mutex()
LEAD_LOCK = Mutex()
WAF_LOCK = Mutex()
CREW_LOCK = Mutex()


def synchronized(lock):
    def deco(fn):
        def wrapper(*a, **kw):
            with lock:
                return fn(*a, **kw)
        return wrapper
    return deco


class PayloadMutexCoordinator:
    """Thread-safe coordinator tracking WAF-blocked payloads, burned User-Agents,
    and working tamper scripts per `(host, vuln_class)` across concurrent workers."""

    def __init__(self):
        self._lock = threading.RLock()
        self._burned: set[tuple[str, str, str, str]] = set()
        self._failed_log: list[dict] = []
        self._working_tampers: dict[str, list[str]] = {}
        self._working_profiles: dict[str, dict] = {}
        self._attempts: dict[str, int] = {}

    def note_attempt(self, host: str):
        with self._lock:
            self._attempts[host] = self._attempts.get(host, 0) + 1

    def is_burned(self, host: str, vuln_class: str, raw_payload: str, tamper: str = "raw") -> bool:
        with self._lock:
            return (host, vuln_class, raw_payload, tamper) in self._burned

    def record_failure(
        self,
        host: str,
        vuln_class: str,
        raw_payload: str,
        tamper: str = "raw",
        status: int = 0,
        ua: str = "",
        reason: str = "waf_block",
    ):
        with self._lock:
            self._burned.add((host, vuln_class, raw_payload, tamper))
            self._failed_log.append({
                "ts": time.time(),
                "host": host,
                "vuln_class": vuln_class,
                "payload": raw_payload,
                "tamper": tamper,
                "status": status,
                "ua": ua,
                "reason": reason,
            })

    def record_bypass_win(self, host: str, tamper: str, profile: dict | None = None):
        with self._lock:
            cur = self._working_tampers.setdefault(host, [])
            if tamper in cur:
                cur.remove(tamper)
            cur.insert(0, tamper)
            if profile:
                self._working_profiles[host] = dict(profile)

    def preferred_tampers(self, host: str) -> list[str]:
        with self._lock:
            return list(self._working_tampers.get(host, []))

    def next_mutations(
        self,
        host: str,
        vuln_class: str,
        raw_payload: str,
        waf_vendors: list[str] | None = None,
        max_variants: int = 6,
    ) -> list[tuple[str, str]]:
        from core.waf_bypass import apply_tamper, prioritize_tampers

        with self._lock:
            ordered = list(self._working_tampers.get(host, []))
        for t in prioritize_tampers(waf_vendors or [], vuln_class=vuln_class):
            if t not in ordered:
                ordered.append(t)

        out: list[tuple[str, str]] = []
        with self._lock:
            for tname in ordered:
                if (host, vuln_class, raw_payload, tname) in self._burned:
                    continue
                try:
                    mut = apply_tamper(tname, raw_payload)
                except Exception:
                    continue
                if mut == raw_payload:
                    continue
                out.append((tname, mut))
                if len(out) >= max_variants:
                    break
        return out

    def snapshot_endpoint(self, url_or_host: str, param: str = "") -> dict:
        import urllib.parse
        host = urllib.parse.urlparse(url_or_host).netloc if "://" in url_or_host else url_or_host
        with self._lock:
            blocked = sorted({t for (h, _vc, _p, t) in self._burned if h == host})
            return {
                "host": host,
                "param": param,
                "attempts": self._attempts.get(host, 0),
                "blocked_tampers": blocked,
                "promoted_tampers": list(self._working_tampers.get(host, [])),
            }

    def stats(self, host: str | None = None) -> dict:
        with self._lock:
            logs = [x for x in self._failed_log if (host is None or x["host"] == host)]
            return {
                "burned_count": len(logs),
                "working_tampers": dict(self._working_tampers),
                "recent_failures": logs[-20:],
            }


PAYLOAD_MUTEX = PayloadMutexCoordinator()
