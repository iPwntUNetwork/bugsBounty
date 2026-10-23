"""Configuration, binary paths, and AI provider settings (Groq + Local Ollama)."""
import json
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BIN_DIR = REPO_ROOT / ".bin"
VENV_BIN_DIR = REPO_ROOT / ".venv" / "bin"

# Prepend repo .bin (compiled native tools) and .venv/bin onto PATH immediately
# so every agent, scanner, and subprocess uses <repo>/.bin/<tool> first!
_path_parts = [str(p) for p in (BIN_DIR, VENV_BIN_DIR, Path.home() / ".local" / "bin", Path.home() / "go" / "bin") if p.exists()]
_cur_path = os.environ.get("PATH", "")
for _p in reversed(_path_parts):
    if _p not in _cur_path.split(os.pathsep):
        _cur_path = _p + (os.pathsep + _cur_path if _cur_path else "")
os.environ["PATH"] = _cur_path

for _c in (REPO_ROOT / ".env", Path.cwd() / ".env", Path.home() / ".bugsBounty" / ".env"):
    if _c.exists():
        for _line in _c.read_text(errors="ignore").splitlines():
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                k, v = _line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

HOME = Path(os.environ.get("BUGHUNTER_HOME", Path.home() / ".bugsBounty")).expanduser()
HOME.mkdir(parents=True, exist_ok=True)
for sub in ("memory", "leads", "reports", "recon", "scans", "logs", "wordlists", "oob", "beef"):
    (HOME / sub).mkdir(parents=True, exist_ok=True)
REPORTS_DIR = HOME / "reports"

CONFIG_FILE = HOME / "config.json"


def load_user_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except Exception:
            return {}
    return {}


def save_user_config(**updates) -> dict:
    cfg = load_user_config()
    for k, v in updates.items():
        if v is not None:
            cfg[k] = v
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
    return cfg


_USER_CFG = load_user_config()


def get_setting(env_key: str, cfg_key: str, default: str = "") -> str:
    if env_key in os.environ and os.environ[env_key] != "":
        return os.environ[env_key]
    if cfg_key in _USER_CFG and _USER_CFG[cfg_key] not in (None, ""):
        return str(_USER_CFG[cfg_key])
    return default


LLM_PROVIDER = (os.environ.get("LLM_PROVIDER") or get_setting("BUGHUNTER_PROVIDER", "provider", "auto")).lower()

GROQ_API_KEY = get_setting("GROQ_API_KEY", "groq_api_key", "")
GROQ_BASE_URL = get_setting("GROQ_BASE_URL", "groq_base_url", "https://api.groq.com/openai/v1")
DEFAULT_MODEL = get_setting("BUGHUNTER_MODEL", "model", "llama-3.3-70b-versatile")
FAST_MODEL = get_setting("BUGHUNTER_FAST_MODEL", "fast_model", "llama-3.1-8b-instant")

OLLAMA_BASE_URL = get_setting("OLLAMA_BASE_URL", "ollama_base_url", "http://localhost:11434")
OLLAMA_MODEL = get_setting("OLLAMA_MODEL", "ollama_model", "llama3.1:8b")
OLLAMA_FAST_MODEL = get_setting("OLLAMA_FAST_MODEL", "ollama_fast_model", "")
OLLAMA_NUM_CTX = int(get_setting("OLLAMA_NUM_CTX", "ollama_num_ctx", "8192"))

AUTH_USERNAME = get_setting("BUGHUNTER_USERNAME", "username", "")
AUTH_PASSWORD = get_setting("BUGHUNTER_PASSWORD", "password", "")
AUTH_LOGIN_URL = get_setting("BUGHUNTER_LOGIN_URL", "login_url", "")
AUTH_USER_FIELD = get_setting("BUGHUNTER_USER_FIELD", "user_field", "username")
AUTH_PASS_FIELD = get_setting("BUGHUNTER_PASS_FIELD", "pass_field", "password")

BEEF_HOST = get_setting("BUGHUNTER_BEEF_HOST", "beef_host", "127.0.0.1")
BEEF_PORT = int(get_setting("BUGHUNTER_BEEF_PORT", "beef_port", "18765"))
OOB_HOST = get_setting("BUGHUNTER_OOB_HOST", "oob_host", "127.0.0.1")
OOB_PORT = int(get_setting("BUGHUNTER_OOB_PORT", "oob_port", "18766"))

STEALTH_MODE = get_setting("BUGHUNTER_STEALTH", "stealth", "true").lower() in ("1", "true", "yes", "on")
CREW_BANTER = get_setting("BUGHUNTER_CREW_BANTER", "crew_banter", "true").lower() in ("1", "true", "yes", "on")

MAX_RPS = float(os.environ.get("BUGHUNTER_MAX_RPS", "25"))
REQUEST_TIMEOUT = int(os.environ.get("BUGHUNTER_TIMEOUT", "15"))
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

LEGAL_NOTICE = (
    "Only scan targets you own or have written authorization to test. "
    "Unauthorized scanning is illegal. You are responsible for your actions."
)

CFG: dict = {
    "llm_provider": LLM_PROVIDER,
    "ollama_model": OLLAMA_MODEL,
    "ollama_base_url": OLLAMA_BASE_URL,
    "rate_limit": MAX_RPS,
    "timeout": REQUEST_TIMEOUT,
    "verify_tls": False,
    "stealth": STEALTH_MODE,
    "crew_banter": CREW_BANTER,
    "proxy": os.environ.get("BUGHUNTER_PROXY", ""),
}

