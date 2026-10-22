"""Parallel swarm: run scanners concurrently with mutex-protected shared state."""
import concurrent.futures
from core.mutex import FINDINGS_LOCK
from core.memory import log_event

def run_scanners_parallel(tasks, max_workers=8):
    """tasks: list of (callable, args, kwargs). Returns flattened findings list."""
    results = []
    def worker(t):
        fn, args, kw = t
        try:
            return fn(*args, **(kw or {}))
        except Exception as e:
            return []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = [ex.submit(worker, t) for t in tasks]
        for f in concurrent.futures.as_completed(futs):
            r = f.result()
            if r:
                with FINDINGS_LOCK:
                    results.extend(r)
    return results
