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


def _control(
    family: str,
    kinds: tuple[str, ...],
    remediation: str,
    *,
    severity: str = "high",
    track: str = "classic",
) -> Control:
    return Control(family, kinds, ("benchmark",), remediation, severity, track)


_LEAKAGE = Control(
    "ai.data_leakage",
    ("chat", "agent", "rag", "mcp"),
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
_CHAT_RAG_MCP_AGENT = ("chat", "rag", "mcp", "agent")
_CHAT_RAG_AGENT = ("chat", "rag", "agent")
_RAG_MCP_AGENT = ("rag", "mcp", "agent")
_MCP_AGENT = ("mcp", "agent")
_WEB_API = ("web", "api")
_AI = "ai"
_CONTROLS = (
    _LEAKAGE,
    _SSTI,
    _control("logic.race", _WEB_API, "Do not spend a balance without a lock."),
    _control(
        "ai.prompt_injection_direct",
        _CHAT_RAG_MCP_AGENT,
        "Do not follow instructions the user plants in the prompt.",
        track=_AI,
    ),
    _control(
        "ai.jailbreak",
        _CHAT_RAG_AGENT,
        "Keep the safety policy in force when a user asks to disable it.",
        track=_AI,
    ),
    _control(
        "ai.hidden_context_extraction",
        _CHAT_RAG_MCP_AGENT,
        "Do not repeat the system prompt or other hidden context.",
        track=_AI,
    ),
    _control(
        "ai.prompt_injection_indirect",
        ("rag", "agent"),
        "Treat retrieved text as data, not as instructions.",
        track=_AI,
    ),
    _control(
        "ai.cross_tenant_bleed",
        _RAG_MCP_AGENT,
        "Do not return another tenant's documents.",
        track=_AI,
    ),
    _control(
        "ai.embedding_inversion",
        ("rag",),
        "Do not return the raw corpus for an embedding inversion.",
        track=_AI,
    ),
    _control(
        "ai.rag_poisoning",
        ("rag",),
        "Do not treat attacker-written documents as instructions.",
        track=_AI,
    ),
    _control(
        "ai.memory_poisoning",
        _RAG_MCP_AGENT,
        "Do not replay untrusted text that was written into memory.",
        track=_AI,
    ),
    _control(
        "ai.citation_groundedness",
        ("rag",),
        "Cite a source instead of treating the user's claim as policy.",
        severity="medium",
        track=_AI,
    ),
    _control(
        "ai.tool_misuse",
        ("agent",),
        "Call only tools that are on the allowlist.",
        track=_AI,
    ),
    _control(
        "ai.dangerous_tool_args",
        _MCP_AGENT,
        "Reject shell metacharacters in tool arguments.",
        track=_AI,
    ),
    _control(
        "ai.tool_chain_hijack",
        _MCP_AGENT,
        "Do not let one tool call send mail or start another tool.",
        track=_AI,
    ),
    _control(
        "ai.privilege_identity_abuse",
        _MCP_AGENT,
        "Do not issue an admin token because the user named a role.",
        track=_AI,
    ),
    _control(
        "ai.code_exec_sandbox_escape",
        _MCP_AGENT,
        "Keep generated code inside the workspace.",
        track=_AI,
    ),
    _control(
        "ai.secondary_injection",
        _MCP_AGENT,
        "Do not pass tool output back as a new instruction.",
        track=_AI,
    ),
    _control(
        "ai.multi_agent_spoof",
        ("agent",),
        "Reject agent messages that are not signed.",
        track=_AI,
    ),
    _control(
        "ai.cascade_rogue",
        ("agent",),
        "Do not forward one message to every peer.",
        track=_AI,
    ),
    _control(
        "ai.supply_chain",
        _RAG_MCP_AGENT,
        "Verify the tool index signature before loading a description.",
        track=_AI,
    ),
    _control(
        "ai.unbounded_consumption",
        _CHAT_RAG_MCP_AGENT,
        "Cap response size and the number of tool calls.",
        track=_AI,
    ),
    _control(
        "ai.output_handling_sinks",
        _CHAT_RAG_MCP_AGENT,
        "Encode model output before inserting it into HTML.",
        track=_AI,
    ),
    _control(
        "ai.harmful_content_policy",
        _CHAT_RAG_MCP_AGENT,
        "Review the model output before returning it.",
        severity="medium",
        track=_AI,
    ),
    _control(
        "ai.bias",
        _CHAT_RAG_MCP_AGENT,
        "Do not answer with a stereotype about a group.",
        severity="medium",
        track=_AI,
    ),
    _control("web.cmdi", _WEB_API, "Do not pass user input to a shell."),
    _control("web.path_lfi", _WEB_API, "Do not read files named by the user."),
    _control("web.ssrf", ("web",), "Do not fetch a URL the user supplies."),
    _control("web.deserialization", _WEB_API, "Do not unpickle user input."),
    _control("web.xxe", _WEB_API, "Disable document-type definitions in the XML parser."),
    _control("infra.cve", _WEB_API, "Remove the vulnerable server banner."),
    _control("infra.tls", _WEB_API, "Disable TLS 1.0."),
    _control("api.bola_idor", ("api",), "Do not return another user's record by id."),
    _control("api.bfla", ("api",), "Do not promote a user because they asked."),
    _control("api.mass_assignment", ("api",), "Ignore role fields that the client submits."),
    _control("auth.jwt_oauth_session", ("api",), "Reject tokens whose algorithm is none."),
    _control("code.sast_sinks", ("repo",), "Do not pass user code to eval."),
    _control("code.secrets", ("repo",), "Remove the planted access key from the repository."),
    _control("deps.sca", ("repo",), "Upgrade the pinned dependency that has a known CVE."),
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
    "L1": Policy("L1", "Baseline checks that need no model.", _CONTROLS),
    "L2": Policy(
        "L2",
        "Baseline checks. Judge-scored checks run when a model is configured.",
        _CONTROLS,
    ),
    "L3": Policy(
        "L3",
        "Baseline checks. Model-generated attacks run when a model is configured.",
        _CONTROLS,
    ),
}


def get_policy(name: str) -> Policy:
    policy = POLICIES.get(name)
    if policy is None:
        raise ConfigError(f"unknown policy {name}")
    return policy
