from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib import error, request
from urllib.parse import urlparse

MAX_RESPONSE_BYTES = 1_048_576


class LLMError(Exception):
    """Raised when an LLM backend fails or returns an unusable response."""


class LLMProvider(Protocol):
    name: str

    def complete(self, system: str, user: str) -> str: ...


def _validate_base_url(base_url: str) -> str:
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"invalid LLM base url (http/https required): {base_url!r}")
    return base_url.rstrip("/")


def _post_json(url: str, payload: dict[str, Any], headers: dict[str, str], timeout: float) -> Any:
    body = json.dumps(payload).encode("utf-8")
    req = request.Request(url, data=body, headers={"Content-Type": "application/json", **headers}, method="POST")
    try:
        with request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - scheme validated in provider init
            raw = resp.read(MAX_RESPONSE_BYTES + 1)
    except (error.URLError, TimeoutError, OSError) as exc:
        raise LLMError(f"request failed: {type(exc).__name__}") from exc

    if len(raw) > MAX_RESPONSE_BYTES:
        raise LLMError("response too large")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LLMError("response is not valid JSON") from exc


@dataclass(frozen=True)
class OllamaProvider:
    """Local models through Ollama's /api/chat endpoint. Incident text never leaves the host by default."""

    model: str
    base_url: str = "http://127.0.0.1:11434"
    timeout: float = 30.0
    name: str = "ollama"

    def __post_init__(self) -> None:
        object.__setattr__(self, "base_url", _validate_base_url(self.base_url))

    def complete(self, system: str, user: str) -> str:
        data = _post_json(
            f"{self.base_url}/api/chat",
            {
                "model": self.model,
                "stream": False,
                "options": {"temperature": 0},
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
            headers={},
            timeout=self.timeout,
        )
        try:
            return str(data["message"]["content"])
        except (KeyError, TypeError) as exc:
            raise LLMError("unexpected Ollama response shape") from exc


@dataclass(frozen=True)
class OpenAICompatProvider:
    """Any OpenAI-compatible /chat/completions server (llama.cpp, vLLM, LM Studio, hosted APIs)."""

    model: str
    base_url: str = "http://127.0.0.1:8080/v1"
    api_key: str | None = field(default=None, repr=False)
    timeout: float = 30.0
    name: str = "openai"

    def __post_init__(self) -> None:
        object.__setattr__(self, "base_url", _validate_base_url(self.base_url))

    def complete(self, system: str, user: str) -> str:
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        data = _post_json(
            f"{self.base_url}/chat/completions",
            {
                "model": self.model,
                "temperature": 0,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
            headers=headers,
            timeout=self.timeout,
        )
        try:
            return str(data["choices"][0]["message"]["content"])
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError("unexpected chat completion response shape") from exc


def build_provider(kind: str, model: str | None, base_url: str | None, api_key: str | None) -> LLMProvider | None:
    kind = (kind or "none").lower()
    if kind == "none":
        return None
    if not model:
        raise ValueError("an LLM model name is required (--llm-model or SOC_LLM_MODEL)")
    if kind == "ollama":
        return OllamaProvider(model=model, base_url=base_url) if base_url else OllamaProvider(model=model)
    if kind == "openai":
        if base_url:
            return OpenAICompatProvider(model=model, base_url=base_url, api_key=api_key)
        return OpenAICompatProvider(model=model, api_key=api_key)
    raise ValueError(f"unknown LLM provider: {kind!r} (expected none, ollama or openai)")
