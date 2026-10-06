"""Pinned Phase 1B engines. Adapters and the installer both read this table."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

License = Literal["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MPL-2.0"]
Kind = Literal["relay", "web", "repo"]

STATIC_PROMPT = "secret"
SSTI_PAYLOAD = "{{7*7}}"


@dataclass(frozen=True)
class EngineSpec:
    name: str
    version: str
    license: License
    kind: Kind
    family: str
    priority: int
    target_kinds: tuple[str, ...]
    upstream: str
    package: str


SPECS: tuple[EngineSpec, ...] = (
    EngineSpec(
        "garak",
        "0.17.0",
        "Apache-2.0",
        "relay",
        "ai.data_leakage",
        50,
        ("chat", "agent", "rag", "mcp"),
        "test.Blank",
        "garak==0.17.0",
    ),
    EngineSpec(
        "promptfoo",
        "0.124.0",
        "MIT",
        "relay",
        "ai.data_leakage",
        40,
        ("chat", "agent", "rag", "mcp"),
        "insidia-static",
        "promptfoo@0.124.0",
    ),
    EngineSpec(
        "pyrit",
        "1.1.0",
        "MIT",
        "relay",
        "ai.data_leakage",
        30,
        ("chat", "agent", "rag", "mcp"),
        "RelayTarget",
        "pyrit==1.1.0",
    ),
    EngineSpec(
        "deepteam",
        "1.0.9",
        "Apache-2.0",
        "relay",
        "ai.data_leakage",
        20,
        ("chat", "agent", "rag", "mcp"),
        "model_callback",
        "deepteam==1.0.9",
    ),
    EngineSpec(
        "mcp-scanner",
        "4.8.5",
        "Apache-2.0",
        "repo",
        "code.mcp",
        40,
        ("repo",),
        "behavioral",
        "cisco-ai-mcp-scanner==4.8.5",
    ),
    EngineSpec(
        "skillspector",
        "2.12.0",
        "Apache-2.0",
        "repo",
        "code.skills",
        40,
        ("repo",),
        "skillspector",
        "skillspector @ git+https://github.com/NVIDIA/SkillSpector.git@v2.12.0",
    ),
    EngineSpec(
        "zap",
        "2.17.0",
        "Apache-2.0",
        "web",
        "web.ssti",
        50,
        ("web", "api"),
        "zap-automation",
        "zap.sh",
    ),
    EngineSpec(
        "nuclei",
        "3.11.1",
        "MIT",
        "web",
        "web.ssti",
        40,
        ("web", "api"),
        "insidia-web-ssti",
        "nuclei",
    ),
    EngineSpec(
        "dalfox",
        "3.2.3",
        "MIT",
        "web",
        "web.ssti",
        30,
        ("web", "api"),
        "dalfox",
        "dalfox",
    ),
    EngineSpec(
        "katana",
        "1.8.0",
        "MIT",
        "web",
        "web.ssti",
        20,
        ("web", "api"),
        "katana",
        "katana",
    ),
    EngineSpec(
        "httpx",
        "1.12.0",
        "MIT",
        "web",
        "web.ssti",
        10,
        ("web", "api"),
        "httpx",
        "httpx",
    ),
    EngineSpec(
        "trivy",
        "0.75.0",
        "Apache-2.0",
        "repo",
        "deps.sca",
        40,
        ("repo",),
        "trivy",
        "trivy",
    ),
    EngineSpec(
        "osv-scanner",
        "2.6.0",
        "Apache-2.0",
        "repo",
        "deps.osv",
        30,
        ("repo",),
        "osv-scanner",
        "osv-scanner",
    ),
    EngineSpec(
        "gitleaks",
        "8.30.1",
        "MIT",
        "repo",
        "code.secrets",
        40,
        ("repo",),
        "gitleaks",
        "gitleaks",
    ),
    EngineSpec(
        "bandit",
        "1.9.4",
        "Apache-2.0",
        "repo",
        "code.python",
        40,
        ("repo",),
        "bandit",
        "bandit==1.9.4",
    ),
    EngineSpec(
        "gosec",
        "2.29.0",
        "Apache-2.0",
        "repo",
        "code.go",
        40,
        ("repo",),
        "gosec",
        "gosec",
    ),
)

BY_NAME: dict[str, EngineSpec] = {spec.name: spec for spec in SPECS}
