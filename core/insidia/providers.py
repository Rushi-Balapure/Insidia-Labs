"""Model providers. A configured host is checked against scope and is not called."""

from __future__ import annotations

from insidia.config import ModelRole
from insidia.errors import ConfigError
from insidia.scope import ScopeHost, check_url

KNOWN_PROVIDERS = frozenset({"openai-compatible", "anthropic", "gemini", "bedrock"})


class ModelProvider:
    """A configured model role. Construction checks scope and does not connect."""


def build_provider(role: ModelRole, scope: tuple[ScopeHost, ...]) -> ModelProvider:
    if role.provider not in KNOWN_PROVIDERS:
        raise ConfigError(f"unknown model provider {role.provider}")
    if role.provider == "openai-compatible":
        return _ChatProvider(role, scope, "/chat/completions")
    if role.provider == "anthropic":
        return _ChatProvider(role, scope, "/v1/messages")
    if role.provider == "gemini":
        return _GeminiProvider(role, scope)
    if role.provider == "bedrock":
        raise ConfigError(
            "Bedrock needs an OpenAI-compatible base_url; set provider to openai-compatible"
        )
    raise ConfigError(f"unknown model provider {role.provider}")


class _ChatProvider(ModelProvider):
    def __init__(self, role: ModelRole, scope: tuple[ScopeHost, ...], path: str) -> None:
        if role.base_url is None or role.model is None:
            raise ConfigError(f"models.{role.name} needs base_url and model")
        check_url(role.base_url.rstrip("/") + path, scope)


class _GeminiProvider(ModelProvider):
    def __init__(self, role: ModelRole, scope: tuple[ScopeHost, ...]) -> None:
        if role.base_url is None or role.model is None:
            raise ConfigError(f"models.{role.name} needs base_url and model")
        check_url(
            f"{role.base_url.rstrip('/')}/models/{role.model}:generateContent",
            scope,
        )
