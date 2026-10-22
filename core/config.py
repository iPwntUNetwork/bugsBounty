"""Configuration and paths for the AI Bug Bounty toolkit."""
import os
from pathlib import Path
# optional .env
for _c in (Path.cwd()/'.env', Path.home()/'.bugsBounty'/'.env'):
    if _c.exists():
        for _line in _c.read_text().splitlines():
            _line=_line.strip()
            if _line and not _line.startswith('#') and '=' in _line:
                k,v=_line.split('=',1)
                os.environ.setdefault(k.strip(), v.strip())

HOME = Path(os.environ.get("BUGHUNTER_HOME", Path.home() / ".bugsBounty")).expanduser()
HOME.mkdir(parents=True, exist_ok=True)
for sub in ("memory", "leads", "reports", "recon", "scans", "logs"):
    (HOME / sub).mkdir(parents=True, exist_ok=True)

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_BASE_URL = os.environ.get("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
DEFAULT_MODEL = os.environ.get("BUGHUNTER_MODEL", "llama-3.3-70b-versatile")

# authenticated scanning
AUTH_USERNAME = os.environ.get("BUGHUNTER_USERNAME", "")
AUTH_PASSWORD = os.environ.get("BUGHUNTER_PASSWORD", "")
AUTH_LOGIN_URL = os.environ.get("BUGHUNTER_LOGIN_URL", "")
AUTH_USER_FIELD = os.environ.get("BUGHUNTER_USER_FIELD", "username")
AUTH_PASS_FIELD = os.environ.get("BUGHUNTER_PASS_FIELD", "password")
FAST_MODEL = os.environ.get("BUGHUNTER_FAST_MODEL", "llama-3.1-8b-instant")

# safety
MAX_RPS = float(os.environ.get("BUGHUNTER_MAX_RPS", "5"))
REQUEST_TIMEOUT = int(os.environ.get("BUGHUNTER_TIMEOUT", "20"))
USER_AGENT = "Mozilla/5.0 (compatible; BugHunter/1.0; +https://github.com/awarexone/Agentic-Bug-Hunter)"

# scope guard: only scan targets the user owns or has permission for
LEGAL_NOTICE = (
    "Only scan targets you own or have written authorization to test. "
    "Unauthorized scanning is illegal. You are responsible for your actions."
)
