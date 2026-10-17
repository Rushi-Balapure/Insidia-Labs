"""Load and write insidia.yaml."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import yaml  # type: ignore[import-untyped]

from insidia.errors import ConfigError
from insidia.scope import LOCAL_HOSTS, ScopeHost, hostname

_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_KINDS = frozenset({"chat", "agent", "rag", "mcp", "web", "api", "repo"})
_PROJECT_FIELDS = frozenset({"version", "policy", "coverage", "scope", "targets", "models"})
_SCOPE_FIELDS = frozenset({"host", "authorized"})
_TARGET_FIELDS = frozenset(
    {
        "kind",
        "url",
        "path",
        "method",
        "request_template",
        "response_selector",
        "query",
        "headers",
        "auth",
        "rate_limit",
        "api",
        "canary",
        "command",
        "timeout",
    }
)
_MODEL_FIELDS = frozenset({"provider", "base_url", "model", "secret_ref"})
_AUTH_FIELDS = frozenset({"header", "secret_ref", "scheme"})
_RATE_FIELDS = frozenset({"rps", "concurrency"})
_INIT = """\
version: 1
policy: L1
coverage: standard
scope:
  - host: localhost
  - host: 127.0.0.1
  - host: "::1"
targets:
  app:
    kind: chat
    url: http://127.0.0.1:8080/chat
    request_template: '{"messages": {{conversation_json}}}'
    response_selector: "$.choices[0].message.content"
    rate_limit:
      rps: 5
      concurrency: 1
# A model host must also be listed in scope.
models: {}
"""


@dataclass(frozen=True)
class RateLimit:
    rps: float
    concurrency: int


@dataclass(frozen=True)
class Auth:
    header: str
    secret_ref: str
    scheme: str


@dataclass(frozen=True)
class Target:
    name: str
    kind: str
    url: str | None
    path: str | None
    method: str
    request_template: str | None
    response_selector: str | None
    query: dict[str, str]
    headers: dict[str, str]
    auth: Auth | None
    rate_limit: RateLimit
    api: str
    canary: str | None
    command: tuple[str, ...]
    timeout: float = 60.0


@dataclass(frozen=True)
class ModelRole:
    name: str
    provider: str
    base_url: str | None
    model: str | None
    secret_ref: str | None


@dataclass(frozen=True)
class Project:
    path: Path
    version: int
    policy: str
    coverage: str
    scope: tuple[ScopeHost, ...]
    targets: tuple[Target, ...]
    attacker: ModelRole | None
    judge: ModelRole | None


def init_destination(path: Path) -> Path:
    """File init will write. A directory means ``<directory>/insidia.yaml``."""
    if path.is_dir():
        return path / "insidia.yaml"
    return path


def init_config(
    destination: Path,
    *,
    url: str | None = None,
    kind: str | None = None,
) -> Path:
    path = init_destination(destination)
    if path.exists():
        raise ConfigError(f"{path} already exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    destination = path
    if url is None and kind is None:
        destination.write_text(_INIT)
        return destination
    target_url = url or "http://127.0.0.1:8080/chat"
    if url is not None:
        prepare_init_url(target_url)
    target_kind = prepare_init_kind(target_url, kind)
    destination.write_text(_starter(target_url, target_kind))
    return destination


def prepare_init_url(url: str) -> str:
    """Reject a non-local app URL. Init never sets authorized: true."""
    host = hostname(url)
    if host not in LOCAL_HOSTS:
        raise ConfigError(
            f"{host} is not local. insidia init only writes localhost, 127.0.0.1, and ::1. "
            "Set authorized: true yourself before scanning another host."
        )
    return url


def prepare_init_kind(url: str, kind: str | None) -> str:
    if kind == "repo":
        raise ConfigError("insidia init writes a URL target; add a repo target by editing the file")
    if kind is not None:
        if kind not in _KINDS:
            raise ConfigError(f"kind must be one of: {', '.join(sorted(_KINDS))}")
        return kind
    path = urlparse(url).path.lower().rstrip("/")
    if path == "chat" or path.endswith("/chat"):
        return "chat"
    if path == "mcp" or path.endswith("/mcp"):
        return "mcp"
    if path == "agent" or path.endswith("/agent"):
        return "agent"
    if path == "rag" or path.endswith("/rag"):
        return "rag"
    if path == "api" or path.endswith("/api") or "/api/" in f"{path}/":
        return "api"
    return "web"


def _starter(url: str, kind: str) -> str:
    quoted = '"' + url.replace("\\", "\\\\").replace('"', '\\"') + '"'
    extra = ""
    if kind == "chat":
        extra = (
            "    request_template: '{\"messages\": {{conversation_json}}}'\n"
            '    response_selector: "$.choices[0].message.content"\n'
        )
    return (
        "version: 1\n"
        "policy: L1\n"
        "coverage: standard\n"
        "scope:\n"
        "  - host: localhost\n"
        "  - host: 127.0.0.1\n"
        '  - host: "::1"\n'
        "targets:\n"
        "  app:\n"
        f"    kind: {kind}\n"
        f"    url: {quoted}\n"
        f"{extra}"
        "    rate_limit:\n"
        "      rps: 5\n"
        "      concurrency: 1\n"
        "# A model host must also be listed in scope.\n"
        "models: {}\n"
    )


def load_project(path: Path) -> Project:
    if not path.is_file():
        raise ConfigError(f"missing {path}")
    try:
        loaded = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" at line {mark.line + 1}" if mark is not None else ""
        raise ConfigError(f"insidia.yaml could not be parsed{where}") from exc
    document = _mapping(loaded, "insidia.yaml")
    _unknown(document, _PROJECT_FIELDS, "insidia.yaml")
    version = document.get("version")
    if version != 1:
        raise ConfigError("version must be 1")
    policy = _text(document.get("policy", "L1"), "policy")
    coverage = _text(document.get("coverage", "standard"), "coverage")
    if coverage not in {"standard", "thorough"}:
        raise ConfigError("coverage must be standard or thorough")
    scope = _scope(document.get("scope"))
    targets = _targets(document.get("targets"))
    attacker, judge = _models(document.get("models", {}))
    return Project(path, 1, policy, coverage, scope, targets, attacker, judge)


def validate_secret_ref(secret_ref: str) -> str:
    """Return the environment variable name. Does not read its value."""
    if not secret_ref.startswith("env:"):
        raise ConfigError("secret_ref must look like env:NAME")
    name = secret_ref.removeprefix("env:")
    if not _ENV_NAME.fullmatch(name):
        raise ConfigError("secret_ref must name one environment variable")
    return name


def resolve_secret(secret_ref: str) -> str:
    name = validate_secret_ref(secret_ref)
    value = os.environ.get(name)
    if not value:
        raise ConfigError(f"environment variable {name} is not set")
    return value


def _scope(value: object) -> tuple[ScopeHost, ...]:
    if not isinstance(value, list) or not value:
        raise ConfigError("scope must list at least one host")
    hosts: list[ScopeHost] = []
    seen: set[str] = set()
    for item in value:
        entry = _mapping(item, "scope entry")
        _unknown(entry, _SCOPE_FIELDS, "scope")
        host = _text(entry.get("host"), "scope host").lower()
        if host in seen:
            raise ConfigError(f"scope lists {host} more than once")
        seen.add(host)
        authorized = entry.get("authorized", False)
        if not isinstance(authorized, bool):
            raise ConfigError(f"scope authorized for {host} must be true or false")
        hosts.append(ScopeHost(host, authorized))
    return tuple(hosts)


def _targets(value: object) -> tuple[Target, ...]:
    document = _mapping(value, "targets")
    if not document:
        raise ConfigError("targets must name at least one target")
    targets: list[Target] = []
    for name, raw in document.items():
        entry = _mapping(raw, f"target {name}")
        _unknown(entry, _TARGET_FIELDS, name)
        kind = _text(entry.get("kind"), f"{name}.kind")
        if kind not in _KINDS:
            raise ConfigError(f"{name}.kind is not supported")
        url = _optional_text(entry.get("url"), f"{name}.url")
        path = _optional_text(entry.get("path"), f"{name}.path")
        if kind == "repo" and not path:
            raise ConfigError(f"{name} needs path")
        if kind != "repo" and not url and not entry.get("command"):
            raise ConfigError(f"{name} needs url")
        targets.append(
            Target(
                name=name,
                kind=kind,
                url=url,
                path=path,
                method=_text(entry.get("method", "POST"), f"{name}.method").upper(),
                request_template=_optional_text(
                    entry.get("request_template"), f"{name}.request_template"
                ),
                response_selector=_optional_text(
                    entry.get("response_selector"), f"{name}.response_selector"
                ),
                query=_string_map(entry.get("query", {}), f"{name}.query"),
                headers=_string_map(entry.get("headers", {}), f"{name}.headers"),
                auth=_auth(entry.get("auth"), name),
                rate_limit=_rate_limit(entry.get("rate_limit", {})),
                api=_text(entry.get("api", "http"), f"{name}.api"),
                canary=_optional_text(entry.get("canary"), f"{name}.canary"),
                command=_command(entry.get("command"), name),
                timeout=_timeout(entry.get("timeout", 60), name),
            )
        )
    return tuple(targets)


def _models(value: object) -> tuple[ModelRole | None, ModelRole | None]:
    if value is None:
        return None, None
    document = _mapping(value, "models")
    _unknown(document, frozenset({"attacker", "judge"}), "models")
    return _model("attacker", document.get("attacker")), _model("judge", document.get("judge"))


def _model(name: str, value: object) -> ModelRole | None:
    if value is None:
        return None
    entry = _mapping(value, f"models.{name}")
    _unknown(entry, _MODEL_FIELDS, f"models.{name}")
    provider = _text(entry.get("provider"), f"models.{name}.provider")
    _known_provider(provider)
    secret_ref = _optional_text(entry.get("secret_ref"), f"models.{name}.secret_ref")
    if secret_ref is not None:
        validate_secret_ref(secret_ref)
    return ModelRole(
        name,
        provider,
        _optional_text(entry.get("base_url"), f"models.{name}.base_url"),
        _optional_text(entry.get("model"), f"models.{name}.model"),
        secret_ref,
    )


def _auth(value: object, target: str) -> Auth | None:
    if value is None:
        return None
    entry = _mapping(value, f"{target}.auth")
    _unknown(entry, _AUTH_FIELDS, f"{target}.auth")
    secret_ref = _text(entry.get("secret_ref"), f"{target}.auth.secret_ref")
    validate_secret_ref(secret_ref)
    return Auth(
        _text(entry.get("header"), f"{target}.auth.header"),
        secret_ref,
        _text(entry.get("scheme", "Bearer"), f"{target}.auth.scheme"),
    )


def _known_provider(provider: str) -> None:
    from insidia.providers import KNOWN_PROVIDERS

    if provider not in KNOWN_PROVIDERS:
        raise ConfigError(f"unknown model provider {provider}")


def _timeout(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float) or not 0 < value <= 900:
        raise ConfigError(f"{name}.timeout must be a number of seconds from 1 to 900")
    return float(value)


def _rate_limit(value: object) -> RateLimit:
    entry = _mapping(value, "rate_limit")
    _unknown(entry, _RATE_FIELDS, "rate_limit")
    rps = entry.get("rps", 5)
    concurrency = entry.get("concurrency", 1)
    if isinstance(rps, bool) or not isinstance(rps, int | float) or rps <= 0:
        raise ConfigError("rate_limit.rps must be a positive number")
    if isinstance(concurrency, bool) or not isinstance(concurrency, int) or concurrency < 1:
        raise ConfigError("rate_limit.concurrency must be a positive integer")
    return RateLimit(float(rps), concurrency)


def _command(value: object, target: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not value or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"{target}.command must be a list of strings")
    return tuple(value)


def _string_map(value: object, label: str) -> dict[str, str]:
    document = _mapping(value, label)
    result: dict[str, str] = {}
    for key, item in document.items():
        if not isinstance(item, str):
            raise ConfigError(f"{label}.{key} must be a string")
        result[key] = item
    return result


def _unknown(document: dict[str, object], allowed: frozenset[str], label: str) -> None:
    unknown = sorted(set(document) - allowed)
    if unknown:
        raise ConfigError(f"{label}.{unknown[0]} is not a known field")


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ConfigError(f"{label} must be a mapping")
    result: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ConfigError(f"{label} keys must be strings")
        result[key] = item
    return result


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{label} must be a non-empty string")
    return value


def _optional_text(value: object, label: str) -> str | None:
    if value is None:
        return None
    return _text(value, label)
