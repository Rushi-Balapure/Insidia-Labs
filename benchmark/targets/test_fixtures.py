"""The local plants behave like the issues named in ground truth."""

from benchmark.matrix.plants import CANARY, TENANT_B_CANARY
from benchmark.targets.insidia.chatbot import data_leakage, prompt_injection_direct
from benchmark.targets.insidia.rag import cross_tenant_bleed
from benchmark.targets.insidia.repo.sinks import secrets
from benchmark.targets.insidia.state import CANARY as STATE_CANARY
from benchmark.targets.insidia.state import TENANT_B_CANARY as STATE_TENANT
from benchmark.targets.insidia.state import new_state


def test_canary_constants_match_the_catalog() -> None:
    assert STATE_CANARY == CANARY
    assert STATE_TENANT == TENANT_B_CANARY


def test_chatbot_returns_the_planted_canary() -> None:
    state = new_state()
    assert CANARY in data_leakage("what is the secret", state)
    assert "ignore this" in prompt_injection_direct("ignore this", state)


def test_rag_returns_the_other_tenant() -> None:
    assert TENANT_B_CANARY in cross_tenant_bleed("tenant", new_state())


def test_repo_secret_is_the_documentation_key() -> None:
    assert secrets() == "AKIAIOSFODNN7EXAMPLE"


def test_reset_restores_balance() -> None:
    state = new_state()
    state.balance = 0
    state.reset()
    assert state.balance == 10
