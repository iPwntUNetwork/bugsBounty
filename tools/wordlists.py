"""Curated built-in wordlists + SecLists resolver for Gobuster, FFUF, and Arjun."""
from pathlib import Path
from core.config import HOME

DEFAULT_DIRS = [
    ".env", ".git/HEAD", "admin", "api", "v1", "v2", "graphql", "login", "dashboard",
    "config", "backup", "robots.txt", "sitemap.xml", "swagger.json", "openapi.json",
    "actuator/env", "actuator/health", "server-status", "phpinfo.php", "debug",
    "internal", "console", "uploads", "secret", "users", "hidden_api",
]

DEFAULT_PARAMS = [
    "id", "q", "search", "query", "url", "uri", "next", "redirect", "return",
    "file", "path", "page", "template", "name", "user", "username", "email",
    "role", "admin", "debug", "test", "cmd", "exec", "ip", "host", "callback",
    "token", "api_key", "key", "secret", "data", "format", "sort", "order",
]


def dir_wordlist(prefer_fast: bool = True) -> str:
    if not prefer_fast:
        seclists = Path("/usr/share/seclists/Discovery/Web-Content/common.txt")
        if seclists.exists():
            return str(seclists)
    out = HOME / "wordlists" / "fast_dirs.txt"
    out.parent.mkdir(parents=True, exist_ok=True)
    if not out.exists():
        out.write_text("\n".join(DEFAULT_DIRS) + "\n")
    return str(out)


def param_wordlist() -> str:
    out = HOME / "wordlists" / "fast_params.txt"
    out.parent.mkdir(parents=True, exist_ok=True)
    if not out.exists():
        out.write_text("\n".join(DEFAULT_PARAMS) + "\n")
    return str(out)


def ensure_wordlist(kind: str = "directories") -> Path:
    if kind.startswith("param"):
        return Path(param_wordlist())
    return Path(dir_wordlist())

