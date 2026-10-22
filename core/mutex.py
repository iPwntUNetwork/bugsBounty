"""Thread-safe mutexes and shared state for parallel swarm."""
import threading

class Mutex:
    def __init__(self):
        self._lock = threading.RLock()
    def __enter__(self):
        self._lock.acquire()
        return self
    def __exit__(self, *a):
        self._lock.release()

# global locks
FINDINGS_LOCK = Mutex()
RATE_LOCK = Mutex()
MEMORY_LOCK = Mutex()
LEAD_LOCK = Mutex()

def synchronized(lock):
    def deco(fn):
        def wrapper(*a, **kw):
            with lock:
                return fn(*a, **kw)
        return wrapper
    return deco
