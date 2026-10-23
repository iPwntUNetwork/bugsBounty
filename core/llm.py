"""Unified LLM client — Groq Cloud (`https://api.groq.com/openai/v1`, default `qwen/qwen3.8-27b`) + Local Ollama (+ OpenAI / xAI)."""
import json
import os
import re
import time
import requests
from core.config import (
    CFG,
    LLM_PROVIDER,
    GROQ_API_KEY,
    GROQ_BASE_URL,
    DEFAULT_MODEL,
    FAST_MODEL,
    XAI_API_KEY,
    XAI_BASE_URL,
    XAI_MODEL,
    OPENAI_API_KEY,
    OPENAI_BASE_URL,
    OPENAI_MODEL,
    OLLAMA_BASE_URL,
    OLLAMA_MODEL,
    OLLAMA_FAST_MODEL,
    OLLAMA_NUM_CTX,
    detect_provider_from_key,
    mask_secret,
    normalize_groq_model,
)

_OLLAMA_CACHE = {"checked_at": 0.0, "alive": False, "models": [], "url": ""}


class _CallableBool(int):
    """Works cleanly BOTH as property (`if llm.available:`) AND method (`if llm.available():`)."""

    def __new__(cls, val: bool):
        return super().__new__(cls, 1 if val else 0)

    def __call__(self) -> bool:
        return bool(self)

    def __bool__(self) -> bool:
        return int(self) != 0

    def __eq__(self, other):
        if isinstance(other, bool):
            return bool(self) is other
        return super().__eq__(other)

    def __repr__(self) -> str:
        return "True" if bool(self) else "False"


def check_ollama(base_url: str | None = None, force: bool = False) -> tuple[bool, list[str]]:
    url = (base_url or CFG.get("ollama_base_url") or os.environ.get("OLLAMA_BASE_URL") or OLLAMA_BASE_URL).rstrip("/")
    now = time.time()
    if not force and _OLLAMA_CACHE["url"] == url and (now - _OLLAMA_CACHE["checked_at"]) < 5.0:
        return _OLLAMA_CACHE["alive"], list(_OLLAMA_CACHE["models"])
    try:
        r = requests.get(f"{url}/api/tags", timeout=2.5)
        if r.status_code == 200:
            data = r.json()
            models = [m.get("name", "") for m in data.get("models", []) if m.get("name")]
            _OLLAMA_CACHE.update({"checked_at": now, "alive": True, "models": models, "url": url})
            return True, models
    except Exception:
        pass
    _OLLAMA_CACHE.update({"checked_at": now, "alive": False, "models": [], "url": url})
    return False, []


def _strip_reasoning(text: str | None) -> str:
    if not text:
        return ""
    cleaned = re.sub(r"<think>.*?</think>", "", text, flags=re.S | re.I).strip()
    if cleaned:
        return cleaned
    # If an unclosed <think> appeared at max_tokens boundary, strip tag marker cleanly
    return re.sub(r"</?think>", "", text, flags=re.I).strip()


def _extract_json(text: str | None):
    if not text:
        return None
    cleaned = _strip_reasoning(text)
    fence = re.search(r"```(?:json)?\s*(\{.*\}|\[.*\])\s*```", cleaned, re.S)
    if fence:
        cleaned = fence.group(1)
    try:
        return json.loads(cleaned)
    except Exception:
        pass
    m = re.search(r"\{.*\}", cleaned, re.S)
    if m:
        candidate = m.group(0)
        try:
            return json.loads(candidate)
        except Exception:
            repaired = re.sub(r",\s*([}\]])", r"\1", candidate)
            try:
                return json.loads(repaired)
            except Exception:
                return None
    return None


class LLM:
    """Primary Groq (`https://api.groq.com/openai/v1`, `qwen/qwen3.8-27b`) + Local Ollama + optional OpenAI / xAI."""

    def __init__(
        self,
        model: str | None = None,
        fast: bool = False,
        provider: str | None = None,
        ollama_url: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
    ):
        raw_provider = (
            provider
            or CFG.get("llm_provider")
            or os.environ.get("LLM_PROVIDER")
            or os.environ.get("BUGHUNTER_PROVIDER")
            or LLM_PROVIDER
            or "auto"
        ).lower()

        groq_k = os.environ.get("GROQ_API_KEY") or GROQ_API_KEY or os.environ.get("GROK_API_KEY") or ""
        xai_k = os.environ.get("XAI_API_KEY") or XAI_API_KEY
        openai_k = os.environ.get("OPENAI_API_KEY") or OPENAI_API_KEY
        any_key = api_key or CFG.get("api_key") or os.environ.get("BUGHUNTER_API_KEY") or ""

        self.ollama_base = (ollama_url or CFG.get("ollama_base_url") or os.environ.get("OLLAMA_BASE_URL") or OLLAMA_BASE_URL).rstrip("/")
        self.ollama_url = self.ollama_base

        if raw_provider == "ollama":
            self.provider = "ollama"
            self.key = ""
        elif raw_provider == "xai":
            self.provider = "xai"
            self.key = any_key or xai_k
        elif raw_provider in ("groq", "grok"):
            candidate = any_key or (xai_k if (any_key or "").startswith("xai-") else groq_k) or xai_k
            self.provider = detect_provider_from_key(candidate, raw_provider)
            if self.provider == "auto":
                self.provider = "groq"
            self.key = candidate
        elif raw_provider == "openai":
            self.provider = "openai"
            self.key = any_key or openai_k
        else:
            candidate = any_key or groq_k or xai_k or openai_k
            if candidate:
                self.provider = detect_provider_from_key(candidate, None)
                self.key = candidate
            else:
                alive, _ = check_ollama(self.ollama_base)
                self.provider = "ollama" if alive else "groq"
                self.key = ""

        explicit_model = model or CFG.get("llm_model") or None
        explicit_base = base_url or CFG.get("llm_base_url") or None

        if self.provider == "ollama":
            env_model = os.environ.get("OLLAMA_MODEL") or CFG.get("ollama_model")
            fast_m = os.environ.get("OLLAMA_FAST_MODEL") or OLLAMA_FAST_MODEL
            chosen = explicit_model or (fast_m if (fast and fast_m) else (env_model or OLLAMA_MODEL))
            alive, installed = check_ollama(self.ollama_base, force=bool(ollama_url))
            if alive and installed and chosen not in installed:
                prefix_match = next((m for m in installed if m.startswith(chosen.split(":")[0])), None)
                chosen = prefix_match or installed[0]
            self.model = chosen
            self.base = self.ollama_base
        elif self.provider == "xai":
            env_m = os.environ.get("XAI_MODEL") or XAI_MODEL
            self.model = explicit_model or env_m
            self.base = (explicit_base or os.environ.get("XAI_BASE_URL") or XAI_BASE_URL).rstrip("/")
        elif self.provider == "openai":
            env_m = os.environ.get("OPENAI_MODEL") or OPENAI_MODEL
            self.model = explicit_model or env_m
            self.base = (explicit_base or os.environ.get("OPENAI_BASE_URL") or OPENAI_BASE_URL).rstrip("/")
        else:
            # Groq (`https://api.groq.com/openai/v1`, default model `qwen/qwen3.8-27b`)
            self.provider = "groq"
            env_model = os.environ.get("GROQ_MODEL") or os.environ.get("BUGHUNTER_MODEL") or DEFAULT_MODEL
            env_fast = os.environ.get("BUGHUNTER_FAST_MODEL") or FAST_MODEL
            self.model = normalize_groq_model(explicit_model or (env_fast if fast else env_model))
            self.base = (explicit_base or os.environ.get("GROQ_BASE_URL") or GROQ_BASE_URL).rstrip("/")

        self.groq_base = self.base

    @property
    def available(self) -> bool:
        if self.provider == "ollama":
            alive, _ = check_ollama(self.ollama_base)
            return bool(alive)
        return bool(self.key)

    def list_ollama_models(self) -> list[str]:
        _, models = check_ollama(self.ollama_base, force=True)
        return models

    def active_provider(self) -> str:
        return f"{self.provider}:{self.model}" if self.available else f"{self.provider}:deterministic"

    def status_summary(self) -> dict:
        ollama_alive, ollama_models = check_ollama(self.ollama_base)
        return {
            "active_provider": self.provider,
            "display_mode": self.active_provider(),
            "active_model": self.model,
            "base_url": self.base,
            "available": bool(self.available),
            "api_key_set": bool(self.key),
            "api_key_masked": mask_secret(self.key) if self.key else "(not set)",
            "groq_key_set": bool(self.key),
            "ollama_url": self.ollama_base,
            "ollama_reachable": ollama_alive,
            "ollama_models": ollama_models,
        }

    def ping(self) -> dict:
        """Quick live health-check against `https://api.groq.com/openai/v1` (with generous budget for Qwen3 `<think>` tokens)."""
        t0 = time.time()
        try:
            reply = self.chat(
                [{"role": "user", "content": "Reply with the single word READY."}],
                temperature=0.0,
                max_tokens=512,
                retries=1,
            )
            return {
                "ok": bool(reply),
                "provider": self.provider,
                "model": self.model,
                "base_url": self.base,
                "latency_ms": round((time.time() - t0) * 1000, 1),
                "reply": (reply or "").strip()[:120],
            }
        except Exception as exc:
            return {
                "ok": False,
                "provider": self.provider,
                "model": self.model,
                "base_url": self.base,
                "latency_ms": round((time.time() - t0) * 1000, 1),
                "error": str(exc),
            }

    def _chat_ollama_raw(self, messages, temperature=0.2, max_tokens=2048, json_mode=False, tools=None, retries=2) -> dict:
        url = f"{self.ollama_base}/api/chat"
        body = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens, "num_ctx": OLLAMA_NUM_CTX},
        }
        if json_mode:
            body["format"] = "json"
        if tools:
            body["tools"] = tools
        last = None
        for i in range(retries):
            try:
                r = requests.post(url, json=body, timeout=180)
                if r.status_code == 404:
                    v1_body = {"model": self.model, "messages": messages, "temperature": temperature, "max_tokens": max_tokens}
                    if json_mode:
                        v1_body["response_format"] = {"type": "json_object"}
                    if tools:
                        v1_body["tools"] = tools
                    r2 = requests.post(f"{self.ollama_base}/v1/chat/completions", json=v1_body, timeout=180)
                    r2.raise_for_status()
                    msg = r2.json()["choices"][0]["message"]
                    return {"content": _strip_reasoning(msg.get("content") or ""), "tool_calls": msg.get("tool_calls") or []}
                r.raise_for_status()
                msg = r.json().get("message", {})
                return {"content": _strip_reasoning(msg.get("content") or ""), "tool_calls": msg.get("tool_calls") or []}
            except Exception as e:
                last = e
                time.sleep(0.5 + i)
        raise RuntimeError(f"Ollama LLM call failed ({self.ollama_base}, model={self.model}): {last}")

    def _chat_openai_compatible(self, messages, temperature=0.2, max_tokens=4096, json_mode=False, retries=3):
        if not self.key:
            return None
        url = f"{self.base}/chat/completions"
        headers = {"Authorization": f"Bearer {self.key}", "Content-Type": "application/json"}
        body = {"model": self.model, "messages": messages, "temperature": temperature, "max_tokens": max_tokens}
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        last = None
        for i in range(retries):
            try:
                r = requests.post(url, headers=headers, json=body, timeout=90)
                if r.status_code == 429:
                    time.sleep(2 ** i)
                    continue
                if r.status_code == 400 and json_mode and "response_format" in body:
                    body.pop("response_format", None)
                    r = requests.post(url, headers=headers, json=body, timeout=90)
                r.raise_for_status()
                msg = r.json()["choices"][0]["message"]
                raw_text = msg.get("content")
                if not raw_text:
                    raw_text = msg.get("reasoning") or msg.get("reasoning_content") or ""
                return _strip_reasoning(raw_text)
            except Exception as e:
                last = e
                time.sleep(1 + i)
        raise RuntimeError(f"{self.provider.upper()} LLM call failed ({self.base}, model={self.model}): {last}")

    _chat_groq = _chat_openai_compatible

    def chat(self, messages, temperature=0.2, max_tokens=4096, json_mode=False, retries=3):
        if not self.available:
            return None
        if self.provider == "ollama":
            return self._chat_ollama_raw(messages, temperature=temperature, max_tokens=max_tokens, json_mode=json_mode, retries=retries)["content"]
        return self._chat_openai_compatible(messages, temperature=temperature, max_tokens=max_tokens, json_mode=json_mode, retries=retries)

    def json(self, messages, **kw):
        txt = self.chat(messages, json_mode=True, **kw)
        return _extract_json(txt)

    complete_json = json

    def run_tool_loop(
        self,
        messages_or_system,
        task_prompt: str | None = None,
        allowed_tools: dict | None = None,
        tools: list | None = None,
        tool_handlers: dict | None = None,
        max_steps: int = 5,
        temperature: float = 0.25,
    ):
        """Supports BOTH native Ollama/OpenAI `tools=[...], tool_handlers={...}` AND JSON schema agent loops."""
        if tools is not None and tool_handlers is not None:
            conv = list(messages_or_system)
            for _ in range(max_steps):
                resp = self._chat_ollama_raw(conv, temperature=temperature, tools=tools)
                tcalls = resp.get("tool_calls") or []
                if not tcalls:
                    return resp.get("content", "")
                conv.append({"role": "assistant", "content": resp.get("content", ""), "tool_calls": tcalls})
                for tc in tcalls:
                    fn_spec = tc.get("function") or {}
                    fn_name = fn_spec.get("name", "")
                    raw_args = fn_spec.get("arguments") or {}
                    args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                    out = tool_handlers[fn_name](args) if fn_name in tool_handlers else {"error": f"unknown tool {fn_name}"}
                    conv.append({"role": "tool", "name": fn_name, "content": json.dumps(out, default=str)})
            return ""

        if not self.available:
            return {"final": "", "banter": [], "tool_calls": []}

        tool_docs = "\n".join(
            f"- `{name}` ({meta.get('args', 'kwargs')}): {meta.get('description', '')}"
            for name, meta in (allowed_tools or {}).items()
        )
        protocol = (
            f"{messages_or_system}\n\n"
            f"You have direct access ONLY to these tools for your job:\n{tool_docs}\n\n"
            "Always reply in valid JSON matching ONE of these two schemas:\n"
            '1) Call a tool: {"banter": "rowdy crew line", "thought": "reasoning", "tool": "<tool_name>", "args": {...}}\n'
            '2) Finish task: {"banter": "rowdy crew line", "thought": "reasoning", "final": "actionable findings & next steps"}'
        )
        messages = [
            {"role": "system", "content": protocol},
            {"role": "user", "content": task_prompt or ""},
        ]
        banter_lines = []
        calls = []
        for _ in range(max_steps):
            res = self.json(messages, temperature=temperature, max_tokens=2048)
            if not isinstance(res, dict):
                break
            if res.get("banter"):
                banter_lines.append(str(res["banter"]))
            tool_name = res.get("tool")
            if tool_name and allowed_tools and tool_name in allowed_tools:
                t_args = res.get("args") or {}
                try:
                    obs = allowed_tools[tool_name]["fn"](**t_args) if isinstance(t_args, dict) else allowed_tools[tool_name]["fn"](t_args)
                    obs_str = json.dumps(obs, default=str)[:2500]
                except Exception as exc:
                    obs = None
                    obs_str = f"Tool error: {exc}"
                calls.append({"tool": tool_name, "args": t_args, "result": obs, "output_preview": obs_str[:400]})
                messages.append({"role": "assistant", "content": json.dumps(res)})
                messages.append({"role": "user", "content": f"OBSERVATION from `{tool_name}`:\n{obs_str}"})
                continue
            return {"final": str(res.get("final") or res.get("thought") or ""), "banter": banter_lines, "tool_calls": calls}
        return {"final": "", "banter": banter_lines, "tool_calls": calls}


def get_llm(
    fast: bool = False,
    provider: str | None = None,
    model: str | None = None,
    ollama_url: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
) -> LLM:
    return LLM(model=model, fast=fast, provider=provider, ollama_url=ollama_url, api_key=api_key, base_url=base_url)
