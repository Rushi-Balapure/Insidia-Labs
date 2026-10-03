"""The compose project is internal-only, and an open network is rejected."""

import pytest

from tests.harness.sandbox import SandboxOpen, assert_closed, load_compose


def test_checked_in_compose_is_closed() -> None:
    assert_closed(load_compose())


def test_host_port_is_rejected() -> None:
    document = load_compose()
    services = document["services"]
    assert isinstance(services, dict)
    services["juice-shop"]["ports"] = ["3000:3000"]
    with pytest.raises(SandboxOpen, match="host port"):
        assert_closed(document)
