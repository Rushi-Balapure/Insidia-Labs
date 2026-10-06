"""Model providers. Prompts are sent to the configured host and are not logged."""

from __future__ import annotations

import json
from collections.abc import Callable

from insidia.config import ModelRole, resolve_secret
from insidia.errors import CliError, ConfigError
from insidia.scope import ScopeHost, check_url
from insidia.transport import read_url

_Body = Callable[[str, str], dict[str, object]]
_Read = Callable[[dict[str, object]], str]


class ModelProvider:
    def complete(self, prompt: str) -> str:
        raise NotImplementedError


def build_provider(role: ModelRole, scope: tuple[ScopeHost, ...]) -> ModelProvider:
    if role.provider == "openai-compatible":
        return _ChatProvider(role, scope, "/chat/completions", _openai_body, _openai_text)
    if role.provider == "anthropic":
        return _ChatProvider(role, scope, "/v1/messages", _anthropic_body, _anthropic_text)
    if role.provider == "gemini":
        return _GeminiProvider(role, scope)
    if role.provider == "insidia-cloud":
        raise ConfigError("Insidia Cloud models need insidia login, which is not in this release")
    if role.provider == "bedrock":
        raise ConfigError(
            "Bedrock needs an OpenAI-compatible base_url; set provider to openai-compatible"
        )
    raise ConfigError(f"unknown model provider {role.provider}")


class _ChatProvider(ModelProvider):
    def __init__(
        self,
        role: ModelRole,
        scope: tuple[ScopeHost, ...],
        path: str,
        body_for: _Body,
        text_from: _Read,
    ) -> None:
        if role.base_url is None or role.model is None:
            raise ConfigError(f"models.{role.name} needs base_url and model")
        self._url = role.base_url.rstrip("/") + path
        check_url(self._url, scope)
        self._scope = scope
        self._role = role
        self._body_for = body_for
        self._text_from = text_from

    def complete(self, prompt: str) -> str:
        model = self._role.model or ""
        body = self._body_for(model, prompt)
        return _post(self._url, self._scope, body, _auth_headers(self._role), self._text_from)


class _GeminiProvider(ModelProvider):
    def __init__(self, role: ModelRole, scope: tuple[ScopeHost, ...]) -> None:
        if role.base_url is None or role.model is None:
            raise ConfigError(f"models.{role.name} needs base_url and model")
        self._url = f"{role.base_url.rstrip('/')}/models/{role.model}:generateContent"
        check_url(self._url, scope)
        self._scope = scope
        self._role = role

    def complete(self, prompt: str) -> str:
        body: dict[str, object] = {"contents": [{"parts": [{"text": prompt}]}]}
        headers = {"Content-Type": "application/json"}
        if self._role.secret_ref:
            headers["x-goog-api-key"] = resolve_secret(self._role.secret_ref)
        return _post(self._url, self._scope, body, headers, _gemini_text)


def _openai_body(model: str, prompt: str) -> dict[str, object]:
    return {"model": model, "messages": [{"role": "user", "content": prompt}]}


def _anthropic_body(model: str, prompt: str) -> dict[str, object]:
    return {
        "model": model,
        "max_tokens": 256,
        "messages": [{"role": "user", "content": prompt}],
    }


def _openai_text(document: dict[str, object]) -> str:
    choices = document.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        raise CliError("model response has no choices")
    message = choices[0].get("message")
    if not isinstance(message, dict) or not isinstance(message.get("content"), str):
        raise CliError("model response has no content")
    return str(message["content"])


def _anthropic_text(document: dict[str, object]) -> str:
    content = document.get("content")
    if not isinstance(content, list) or not content or not isinstance(content[0], dict):
        raise CliError("model response has no content")
    text = content[0].get("text")
    if not isinstance(text, str):
        raise CliError("model response has no content")
    return text


def _gemini_text(document: dict[str, object]) -> str:
    candidates = document.get("candidates")
    if not isinstance(candidates, list) or not candidates or not isinstance(candidates[0], dict):
        raise CliError("model response has no candidates")
    content = candidates[0].get("content")
    if not isinstance(content, dict):
        raise CliError("model response has no content")
    parts = content.get("parts")
    if not isinstance(parts, list) or not parts or not isinstance(parts[0], dict):
        raise CliError("model response has no content")
    text = parts[0].get("text")
    if not isinstance(text, str):
        raise CliError("model response has no content")
    return text


def _auth_headers(role: ModelRole) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if role.provider == "anthropic":
        headers["anthropic-version"] = "2023-06-01"
    if role.secret_ref:
        secret = resolve_secret(role.secret_ref)
        if role.provider == "anthropic":
            headers["x-api-key"] = secret
        else:
            headers["Authorization"] = f"Bearer {secret}"
    return headers


def _post(
    url: str,
    scope: tuple[ScopeHost, ...],
    body: dict[str, object],
    headers: dict[str, str],
    read: _Read,
) -> str:
    raw = read_url(
        url,
        scope,
        method="POST",
        body=json.dumps(body).encode(),
        headers=headers,
        timeout=30,
    )
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CliError("model response was not JSON") from exc
    if not isinstance(document, dict):
        raise CliError("model response was not a JSON object")
    return read(document)
