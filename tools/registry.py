"""Central Tool Registry resolving binaries from `<repo>/.bin` first and scoping tools per agent role."""
from dataclasses import dataclass
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
from typing import Callable, Any
from core.config import BIN_DIR, VENV_BIN_DIR, REPO_ROOT

DOTBIN = BIN_DIR


@dataclass
class ToolSpec:
    name: str
    category: str
    roles: list[str]
    description: str
    args_schema: str
    fn: Callable[..., Any]
    binary_name: str | None = None
    has_native_fallback: bool = True


_REGISTRY: dict[str, ToolSpec] = {}
_PLUGINS_LOADED = False


def resolve_binary(binary_name: str | None) -> str | None:
    """Resolve executable strictly checking `<repo>/.bin/<name>` FIRST, then venv/local/go/PATH."""
    if not binary_name:
        return None
    for d in (BIN_DIR, VENV_BIN_DIR, Path.home() / ".local" / "bin", Path.home() / "go" / "bin"):
        cand = d / binary_name
        if cand.exists() and cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
    return shutil.which(binary_name)


def exec_binary(
    binary_name: str,
    args: list[str],
    stdin_text: str | None = None,
    timeout: int = 60,
    cwd: str | None = None,
    extra_env: dict | None = None,
) -> dict:
    exe = resolve_binary(binary_name)
    if not exe:
        return {
            "ok": False,
            "binary": None,
            "source": "missing",
            "returncode": -1,
            "stdout": "",
            "stderr": f"Binary '{binary_name}' not found",
        }
    source = ".bin" if Path(exe).resolve().parent == BIN_DIR.resolve() or str(exe).startswith(str(BIN_DIR)) else "path"
    env = dict(os.environ)
    env["PATH"] = f"{BIN_DIR}{os.pathsep}{VENV_BIN_DIR}{os.pathsep}{env.get('PATH', '')}"
    if extra_env:
        env.update(extra_env)
    try:
        proc = subprocess.run(
            [exe] + [str(a) for a in args],
            input=stdin_text,
            text=True,
            capture_output=True,
            timeout=timeout,
            cwd=cwd or str(REPO_ROOT),
            env=env,
        )
        return {
            "ok": proc.returncode == 0 or bool(proc.stdout.strip()),
            "binary": exe,
            "source": source,
            "returncode": proc.returncode,
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
        }
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode(errors="ignore") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        err = exc.stderr.decode(errors="ignore") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return {
            "ok": bool(out.strip()),
            "binary": exe,
            "source": source,
            "returncode": 124,
            "stdout": out,
            "stderr": f"timeout after {timeout}s: {err[:300]}",
        }
    except Exception as exc:
        return {
            "ok": False,
            "binary": exe,
            "source": source,
            "returncode": -1,
            "stdout": "",
            "stderr": str(exc),
        }


def register_tool(
    name: str,
    category: str,
    roles: list[str],
    description: str,
    args_schema: str = "",
    binary_name: str | None = None,
    has_native_fallback: bool = True,
):
    def deco(fn: Callable[..., Any]):
        _REGISTRY[name] = ToolSpec(
            name=name,
            category=category,
            roles=list(roles),
            description=description,
            args_schema=args_schema,
            fn=fn,
            binary_name=binary_name,
            has_native_fallback=has_native_fallback,
        )
        return fn
    return deco


def load_plugins():
    global _PLUGINS_LOADED
    if _PLUGINS_LOADED:
        return
    _PLUGINS_LOADED = True
    import tools.adapters  # noqa: F401
    pdir = Path(__file__).resolve().parent / "plugins"
    if not pdir.exists():
        return
    for pyfile in sorted(pdir.glob("*.py")):
        if pyfile.name.startswith("_"):
            continue
        spec = importlib.util.spec_from_file_location(f"tools.plugins.{pyfile.stem}", pyfile)
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)


def get_tool(name: str) -> ToolSpec | None:
    load_plugins()
    return _REGISTRY.get(name)


def run_tool(name: str, **kwargs):
    load_plugins()
    spec = _REGISTRY.get(name)
    if not spec:
        raise KeyError(f"Unknown tool: {name}. Registered: {sorted(_REGISTRY.keys())}")
    return spec.fn(**kwargs)


def list_tools() -> list[ToolSpec]:
    load_plugins()
    return [_REGISTRY[k] for k in sorted(_REGISTRY.keys())]


def tools_for_role(role: str) -> dict[str, dict]:
    load_plugins()
    out = {}
    for spec in list_tools():
        if role in spec.roles:
            out[spec.name] = {
                "description": spec.description,
                "args": spec.args_schema,
                "category": spec.category,
                "binary": resolve_binary(spec.binary_name) if spec.binary_name else "builtin",
                "fn": spec.fn,
            }
    return out


def inventory_report() -> list[dict]:
    load_plugins()
    rows = []
    for spec in list_tools():
        bpath = resolve_binary(spec.binary_name) if spec.binary_name else None
        in_dot_bin = bool(bpath and str(BIN_DIR.resolve()) in str(Path(bpath).parent.resolve()))
        rows.append({
            "name": spec.name,
            "category": spec.category,
            "binary_name": spec.binary_name or "(built-in)",
            "binary_path": bpath or ("(built-in python)" if not spec.binary_name else "(fallback active)"),
            "in_dot_bin": in_dot_bin if spec.binary_name else True,
            "ready": bool(bpath or spec.has_native_fallback),
            "available": bool(bpath or spec.has_native_fallback),
            "roles": spec.roles,
            "description": spec.description,
        })
    return rows


class ToolRegistry:
    @staticmethod
    def binary_path(name: str) -> Path | None:
        exe = resolve_binary(name)
        return Path(exe) if exe else None

    @staticmethod
    def audit() -> list[dict]:
        rows = []
        probe_flags = {
            "nikto": ["-Version"],
            "gobuster": ["--version"],
            "ffuf": ["-V"],
            "dalfox": ["version"],
            "sqlmap": ["--version"],
            "commix": ["--version"],
            "wafw00f": ["--version"],
            "arjun": ["--help"],
            "paramspider": ["--help"],
            "hakrawler": ["-help"],
            "assetfinder": ["-h"],
            "waybackurls": ["-h"],
            "gau": ["--version"],
            "nuclei": ["-version"],
        }
        for row in inventory_report():
            bname = row["binary_name"]
            if bname == "(built-in)":
                rows.append({
                    "name": row["name"],
                    "category": row["category"],
                    "source": "builtin",
                    "status": "READY",
                    "version": row["description"][:80],
                })
                continue
            flags = probe_flags.get(bname, ["-version"])
            r = exec_binary(bname, flags, timeout=20)
            joined = (r["stdout"] or "") + "\n" + (r["stderr"] or "")
            lines = [ln.strip() for ln in joined.splitlines() if ln.strip()]
            ver = lines[0] if lines else "ok"
            bad = ("traceback (most recent" in joined.lower()) or ("error: required module" in joined.lower())
            ready = bool(r["binary"]) and (not bad) and (r["returncode"] in (0, 1, 2) or bool(lines))
            rows.append({
                "name": row["name"],
                "category": row["category"],
                "source": r["source"],
                "status": "READY" if ready else "MISSING",
                "version": ver,
            })
        return rows
