"""Configuration, binary paths, and AI provider settings (Groq Cloud `qwen/qwen3.8-27b` + Local Ollama + OpenAI/xAI)."""
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

DEPRECATED_GROQ_MODELS = {
    "llama-3.3-70b-versatile",
    "llama-3.1-70b-versatile",
    "llama-3.1-8b-instant",
    "llama3-70b-8192",
    "llama3-8b-8192",
    "mixtral-8x7b-32768",
    "gemma2-9b-it",
}


def mask_secret(secret: str | None) -> str:
    if not secret:
        return "(not set)"
    s = secret.strip()
    if len(s) <= 8:
        return s[:2] + "****"
    return f"{s[:4]}...{s[-4:]}"


def detect_provider_from_key(api_key: str | None, explicit_provider: str | None = None) -> str:
    """Resolve provider cleanly — Groq (`https://api.groq.com/openai/v1`) is the primary default!"""
    k = (api_key or "").strip()
    exp = (explicit_provider or "").strip().lower()
    if k.startswith("xai-") or exp == "xai":
        return "xai"
    if k.startswith("gsk_"):
        return "groq"
    if exp in ("groq", "grok"):
        # People often spell Groq as 'grok' — route to Groq (`https://api.groq.com/openai/v1`) unless key is `xai-...`!
        return "groq"
    if exp in ("openai", "ollama"):
        return exp
    if k.startswith("sk-"):
        return "openai"
    return "groq" if k else "auto"


def _migrate_legacy_config(cfg: dict) -> tuple[dict, bool]:
    """Heal stale decommissioned Groq models (`llama-3.3-70b-versatile`) or misrouted `grok` entries automatically."""
    changed = False
    saved_xai = str(cfg.get("xai_api_key") or cfg.get("grok_api_key") or "").strip()
    if not saved_xai.startswith("xai-"):
        # If an earlier run stored a non-xAI key under grok_api_key or set provider='grok', restore it to Groq!
        if saved_xai and not cfg.get("groq_api_key"):
            cfg["groq_api_key"] = saved_xai
            changed = True
        if cfg.get("provider") == "grok":
            cfg["provider"] = "groq"
            changed = True
    for mk in ("model", "fast_model", "groq_model"):
        if cfg.get(mk) in DEPRECATED_GROQ_MODELS:
            cfg[mk] = "qwen/qwen3.8-27b"
            changed = True
    if cfg.get("groq_base_url") and "api.x.ai" in str(cfg.get("groq_base_url")):
        cfg["groq_base_url"] = "https://api.groq.com/openai/v1"
        changed = True
    return cfg, changed


def load_user_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            cfg = json.loads(CONFIG_FILE.read_text())
            cfg, changed = _migrate_legacy_config(cfg)
            if changed:
                CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
                try:
                    os.chmod(CONFIG_FILE, 0o600)
                except OSError:
                    pass
            return cfg
        except Exception:
            return {}
    return {}


def save_user_config(**updates) -> dict:
    cfg = load_user_config()
    for k, v in updates.items():
        if v is not None:
            cfg[k] = v
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
    try:
        os.chmod(CONFIG_FILE, 0o600)
    except OSError:
        pass
    return cfg


_USER_CFG = load_user_config()


def get_setting(env_key: str, cfg_key: str, default: str = "") -> str:
    if env_key in os.environ and os.environ[env_key] != "":
        return os.environ[env_key]
    if cfg_key in _USER_CFG and _USER_CFG[cfg_key] not in (None, ""):
        return str(_USER_CFG[cfg_key])
    return default


def normalize_groq_model(model_name: str | None) -> str:
    m = (model_name or "").strip()
    if not m or m in DEPRECATED_GROQ_MODELS:
        return "qwen/qwen3.8-27b"
    return m


LLM_PROVIDER = (os.environ.get("LLM_PROVIDER") or get_setting("BUGHUNTER_PROVIDER", "provider", "auto")).lower()

# Groq Cloud (PRIMARY DEFAULT -> https://api.groq.com/openai/v1, model: qwen/qwen3.8-27b)
GROQ_API_KEY = (
    os.environ.get("GROQ_API_KEY")
    or get_setting("GROQ_API_KEY", "groq_api_key", "")
    or (os.environ.get("GROK_API_KEY", "") if not os.environ.get("GROK_API_KEY", "").startswith("xai-") else "")
)
GROQ_BASE_URL = get_setting("GROQ_BASE_URL", "groq_base_url", "https://api.groq.com/openai/v1")
DEFAULT_MODEL = normalize_groq_model(get_setting("GROQ_MODEL", "groq_model", get_setting("BUGHUNTER_MODEL", "model", "qwen/qwen3.8-27b")))
FAST_MODEL = normalize_groq_model(get_setting("BUGHUNTER_FAST_MODEL", "fast_model", "qwen/qwen3.8-27b"))

# Optional xAI (`xai-...` keys only -> https://api.x.ai/v1)
XAI_API_KEY = os.environ.get("XAI_API_KEY") or get_setting("XAI_API_KEY", "xai_api_key", "")
XAI_BASE_URL = get_setting("XAI_BASE_URL", "xai_base_url", "https://api.x.ai/v1")
XAI_MODEL = get_setting("XAI_MODEL", "xai_model", "grok-3")

# Optional OpenAI (`sk-...` keys -> https://api.openai.com/v1)
OPENAI_API_KEY = get_setting("OPENAI_API_KEY", "openai_api_key", "")
OPENAI_BASE_URL = get_setting("OPENAI_BASE_URL", "openai_base_url", "https://api.openai.com/v1")
OPENAI_MODEL = get_setting("OPENAI_MODEL", "openai_model", "gpt-4o-mini")

# Local Ollama
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
    "api_key": "",
    "llm_model": "",
    "llm_base_url": "",
    "ollama_model": OLLAMA_MODEL,
    "ollama_base_url": OLLAMA_BASE_URL,
    "rate_limit": MAX_RPS,
    "timeout": REQUEST_TIMEOUT,
    "verify_tls": False,
    "stealth": STEALTH_MODE,
    "crew_banter": CREW_BANTER,
    "proxy": os.environ.get("BUGHUNTER_PROXY", ""),
}


def configure_api_key(
    api_key: str | None = None,
    provider: str | None = None,
    model: str | None = None,
    base_url: str | None = None,
    persist: bool = True,
) -> dict:
    """Activate an API key / provider immediately in memory AND optionally persist to ~/.bugsBounty/config.json (0600)."""
    key = (api_key or "").strip()
    resolved = detect_provider_from_key(key, provider)
    if resolved == "auto":
        resolved = "groq"
    updates: dict = {}

    if resolved == "ollama":
        CFG["llm_provider"] = "ollama"
        updates["provider"] = "ollama"
        if model:
            CFG["ollama_model"] = model
            os.environ["OLLAMA_MODEL"] = model
            updates["ollama_model"] = model
        if base_url:
            CFG["ollama_base_url"] = base_url
            os.environ["OLLAMA_BASE_URL"] = base_url
            updates["ollama_base_url"] = base_url
    else:
        CFG["llm_provider"] = resolved
        updates["provider"] = resolved
        if key:
            CFG["api_key"] = key
            if resolved == "groq":
                os.environ["GROQ_API_KEY"] = key
                updates["groq_api_key"] = key
            elif resolved == "xai":
                os.environ["XAI_API_KEY"] = key
                updates["xai_api_key"] = key
            elif resolved == "openai":
                os.environ["OPENAI_API_KEY"] = key
                updates["openai_api_key"] = key
        if model is not None:
            clean_model = normalize_groq_model(model) if resolved == "groq" and model else model
            CFG["llm_model"] = clean_model
            if clean_model:
                if resolved == "groq":
                    os.environ["GROQ_MODEL"] = clean_model
                    os.environ["BUGHUNTER_MODEL"] = clean_model
                    updates["groq_model"] = clean_model
                    updates["model"] = clean_model
                    updates["fast_model"] = clean_model
                elif resolved == "xai":
                    os.environ["XAI_MODEL"] = clean_model
                    updates["xai_model"] = clean_model
                elif resolved == "openai":
                    os.environ["OPENAI_MODEL"] = clean_model
                    updates["openai_model"] = clean_model
        if base_url:
            CFG["llm_base_url"] = base_url
            updates[f"{resolved}_base_url"] = base_url

    if persist and updates:
        _USER_CFG.update(save_user_config(**updates))

    return {
        "provider": CFG["llm_provider"],
        "key_masked": mask_secret(key) if key else None,
        "model": CFG.get("llm_model") or "",
        "config_file": str(CONFIG_FILE) if persist else None,
    }
