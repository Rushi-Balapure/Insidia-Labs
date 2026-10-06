from insidia.errors import ScopeError
from insidia.scope import LOCAL_HOSTS, ScopeHost, check_url, needs_confirmation

LOCAL = (ScopeHost("localhost", False), ScopeHost("127.0.0.1", False))


def test_localhost_is_in_scope_without_authorization() -> None:
    assert "localhost" in LOCAL_HOSTS
    assert check_url("http://localhost:8080/chat", LOCAL) == "localhost"


def test_unlisted_host_is_rejected() -> None:
    try:
        check_url("http://example.com/chat", LOCAL)
    except ScopeError as exc:
        assert "not in scope" in str(exc)
    else:
        raise AssertionError("expected ScopeError")


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
