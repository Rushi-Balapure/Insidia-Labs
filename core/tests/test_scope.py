from pathlib import Path

import pytest
from insidia.cli import main
from insidia.errors import ScopeError
from insidia.scope import (
    LOCAL_HOSTS,
    ScopeHost,
    check_url,
    needs_confirmation,
    redirect_refusal,
    unauthorized_host,
)

LOCAL = (ScopeHost("localhost", False), ScopeHost("127.0.0.1", False))


def test_localhost_is_in_scope_without_authorization() -> None:
    assert "localhost" in LOCAL_HOSTS
    assert check_url("http://localhost:8080/chat", LOCAL) == "localhost"
    assert check_url("http://127.0.0.1:6379/redis", LOCAL) == "127.0.0.1"
    local = (*LOCAL, ScopeHost("::1", False))
    assert check_url("http://[::1]:9/", local) == "::1"


def test_unlisted_host_is_rejected() -> None:
    try:
        check_url("http://example.com/chat", LOCAL)
    except ScopeError as exc:
        assert "not in scope" in str(exc)
    else:
        raise AssertionError("expected ScopeError")


def test_redirect_refusal_blocks_port_changes_and_downgrades() -> None:
    assert redirect_refusal("http://127.0.0.1:8080/a", "http://127.0.0.1:8080/b") is None
    assert redirect_refusal("http://127.0.0.1/", "http://127.0.0.1:80/b") is None
    assert redirect_refusal("https://127.0.0.1/a", "https://127.0.0.1:443/b") is None
    assert redirect_refusal("http://127.0.0.1:8443/a", "https://127.0.0.1:8443/a") is None
    assert (
        redirect_refusal("http://127.0.0.1:8080/a", "http://127.0.0.1:6379/")
        == "redirect changed port"
    )
    assert (
        redirect_refusal("https://127.0.0.1:8443/r", "http://127.0.0.1:8443/")
        == "redirect downgraded https to http"
    )
    assert (
        redirect_refusal("https://127.0.0.1/a", "http://127.0.0.1/a")
        == "redirect downgraded https to http"
    )
    assert (
        redirect_refusal("wss://127.0.0.1/a", "ws://127.0.0.1/a") == "redirect downgraded wss to ws"
    )
    assert (
        redirect_refusal("http://127.0.0.1:8080/a", "http://localhost:8080/a")
        == "redirect left 127.0.0.1"
    )


def test_remote_host_needs_authorization_and_confirmation() -> None:
    scope = (ScopeHost("staging.example.com", False),)
    try:
        check_url("https://staging.example.com/chat", scope)
    except ScopeError as exc:
        assert "authorized: true" in str(exc)
    else:
        raise AssertionError("expected ScopeError")
    allowed = (ScopeHost("staging.example.com", True),)
    assert check_url("https://staging.example.com/chat", allowed) == "staging.example.com"
    assert needs_confirmation(allowed)
    assert not needs_confirmation(LOCAL)


def test_unauthorized_host_is_reported_before_confirmation() -> None:
    assert unauthorized_host((ScopeHost("qa-out-of-scope.invalid", False),)) == (
        "qa-out-of-scope.invalid"
    )
    assert unauthorized_host(LOCAL) is None
    assert unauthorized_host((ScopeHost("::1", False), ScopeHost("example.com", True))) is None


def test_scan_names_authorized_before_yes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "insidia.yaml"
    config.write_text(
        """
version: 1
policy: L1
coverage: standard
scope:
  - host: qa-out-of-scope.invalid
  - host: 127.0.0.1
targets:
  app:
    kind: chat
    url: http://127.0.0.1:9/chat
"""
    )

    def explode(*_args: object, **_kwargs: object) -> str:
        raise AssertionError("probed")

    monkeypatch.setattr("insidia.scan.preflight", explode)
    assert main(["scan", "--config", str(config)]) == 2
    out = capsys.readouterr().out
    assert "qa-out-of-scope.invalid needs authorized: true" in out
    assert "pass --yes" not in out
    assert main(["--yes", "scan", "--config", str(config)]) == 2
    assert "needs authorized: true" in capsys.readouterr().out


def test_authorized_remote_host_still_needs_yes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "insidia.yaml"
    config.write_text(
        """
version: 1
policy: L1
coverage: standard
scope:
  - host: example.com
    authorized: true
targets:
  app:
    kind: chat
    url: http://example.com/chat
"""
    )
    assert main(["scan", "--config", str(config)]) == 2
    out = capsys.readouterr().out
    assert "pass --yes" in out
    assert "needs authorized" not in out
