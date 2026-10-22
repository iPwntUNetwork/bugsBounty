"""LLM client for Groq (OpenAI-compatible)."""
import json
import time
import os
import requests
from core.config import GROQ_API_KEY, GROQ_BASE_URL, DEFAULT_MODEL, FAST_MODEL


class LLM:
    def __init__(self, model=None, fast=False):
        self.base = GROQ_BASE_URL.rstrip("/")
        self.key = GROQ_API_KEY
        self.model = model or (FAST_MODEL if fast else DEFAULT_MODEL)
        if fast and model is None:
            self.model = FAST_MODEL

    def available(self):
        return bool(self.key)

    def chat(self, messages, temperature=0.2, max_tokens=2048, json_mode=False, retries=3):
        if not self.key:
            return None
        url = f"{self.base}/chat/completions"
        headers = {"Authorization": f"Bearer {self.key}", "Content-Type": "application/json"}
        body = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        last = None
        for i in range(retries):
            try:
                r = requests.post(url, headers=headers, json=body, timeout=90)
                if r.status_code == 429:
                    time.sleep(2 ** i)
                    continue
                r.raise_for_status()
                data = r.json()
                return data["choices"][0]["message"]["content"]
            except Exception as e:
                last = e
                time.sleep(1 + i)
        raise RuntimeError(f"LLM call failed: {last}")

    def json(self, messages, **kw):
        txt = self.chat(messages, json_mode=True, **kw)
        if txt is None:
            return None
        try:
            return json.loads(txt)
        except Exception:
            import re
            m = re.search(r"\{.*\}", txt, re.S)
            if m:
                try:
                    return json.loads(m.group(0))
                except Exception:
                    return None
            return None


def get_llm(fast=False):
    return LLM(fast=fast)
