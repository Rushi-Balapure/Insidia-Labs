"""Built-in scan policies. L1 is the baseline that needs no model."""

from __future__ import annotations

from dataclasses import dataclass

from insidia.errors import ConfigError


@dataclass(frozen=True)
class Control:
    family: str
    kinds: tuple[str, ...]
    taxonomy: tuple[str, ...]
    remediation: str
    severity: str
    track: str


_LEAKAGE = Control(
    "ai.data_leakage",
    ("chat", "agent", "rag"),
    ("owasp-llm:LLM02",),
    "Stop returning secrets from the prompt, retrieved documents, or tool output.",
    "high",
    "ai",
)
_SSTI = Control(
    "web.ssti",
    ("web", "api"),
    ("owasp-web:A03", "cwe:CWE-1336"),
    "Do not evaluate user input as a template.",
    "high",
    "classic",
)


@dataclass(frozen=True)
class Policy:
    name: str
    summary: str
    controls: tuple[Control, ...]

    def families(self, kind: str) -> tuple[str, ...]:
        return tuple(control.family for control in self.controls if kind in control.kinds)

    def control(self, family: str) -> Control:
        for control in self.controls:
            if control.family == family:
                return control
        raise ConfigError(f"unknown control {family}")


POLICIES: dict[str, Policy] = {
    "L1": Policy("L1", "Baseline checks that need no model.", (_LEAKAGE, _SSTI)),
    "L2": Policy(
        "L2",
        "Baseline checks. Judge-scored checks run when a model is configured.",
        (_LEAKAGE, _SSTI),
    ),
    "L3": Policy(
        "L3",
        "Baseline checks. Model-generated attacks run when a model is configured.",
        (_LEAKAGE, _SSTI),
    ),
}


def get_policy(name: str) -> Policy:
    policy = POLICIES.get(name)
    if policy is None:
        raise ConfigError(f"unknown policy {name}")
    return policy
