"""Open redirects are flagged from the 3xx itself. The external host is not contacted."""

import json
import socket
import threading
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from insidia.cli import main
from insidia.policy import get_policy
from insidia.probes import _redirect_evidence

_HOST = "insidia-redirect.invalid"
_HTTPS = f"https://{_HOST}/"
_SCHEMELESS = f"//{_HOST}"
Reply = Callable[[str, str], tuple[int, str, dict[str, str]]]


def _vulnerable(path: str, nxt: str) -> tuple[int, str, dict[str, str]]:
    if path != "/v1/go":
        return 404, "missing", {}
    if nxt in {_HTTPS, _SCHEMELESS}:
        return 302, "", {"Location": nxt}
    return 302, "", {"Location": "/no-such-route"}


def _meta(path: str, nxt: str) -> tuple[int, str, dict[str, str]]:
    if nxt == _HTTPS:
        body = f'<meta http-equiv="refresh" content="0;url={_HTTPS}">'
        return 200, body, {"Content-Type": "text/html"}
    return 200, "ok", {}


def _relative_only(path: str, nxt: str) -> tuple[int, str, dict[str, str]]:
    del path
    if nxt.startswith("/") and not nxt.startswith("//") and "://" not in nxt:
        return 302, "", {"Location": nxt}
    return 400, "absolute URLs are not allowed", {}


@pytest.fixture
def redirect_app() -> Iterator[Callable[[Reply], int]]:
    reply: dict[str, Reply] = {"fn": _relative_only}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            nxt = parse_qs(parsed.query).get("next", [""])[0]
            status, body, extra = reply["fn"](parsed.path, nxt)
            raw = body.encode()
            self.send_response(status)
            for name, value in extra.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def use(fn: Reply) -> int:
        reply["fn"] = fn
        return int(server.server_address[1])

    yield use
    server.shutdown()
    server.server_close()


def _scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, port: int
) -> tuple[int, list[dict[str, object]], dict[str, object]]:
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(tmp_path / "toolchain"))
    config = tmp_path / "insidia.yaml"
    config.write_text(
        f"""\
version: 1
scope:
  - host: 127.0.0.1
targets:
  redirect:
    kind: api
    url: http://127.0.0.1:{port}/v1/go
    method: GET
    query:
      next: "{{{{payload}}}}"
"""
    )
    code = main(["scan", "--config", str(config), "--quiet"])
    runs = tmp_path / ".insidia" / "runs"
    latest = max(runs.iterdir(), key=lambda path: path.name)
    findings = json.loads((latest / "findings.json").read_text())
    benchmark = json.loads((latest / "benchmark.json").read_text())
    return code, findings, benchmark


def test_open_redirect_control_names_the_issue() -> None:
    control = get_policy("L1").control("web.open_redirect")
    assert control.kinds == ("web", "api")
    assert "owasp-web:A01" in control.taxonomy
    assert "CWE-601" in control.remediation


def test_client_redirects_need_a_refresh_or_script() -> None:
    assert _redirect_evidence(302, {"location": "/home"}, "") is None
    echoed = f"you asked for {_HTTPS}"
    assert _redirect_evidence(200, {}, echoed) is None
    script = f'<script>location.href="{_HTTPS}x"</script>'
    assert _redirect_evidence(200, {}, script) == f"client redirect to {_HTTPS}x"
    other = "https://insidia-redirect.invalid.evil/"
    assert _redirect_evidence(302, {"location": other}, "") is None


def test_open_redirect_is_caught_without_following(
    redirect_app: Callable[[Reply], int],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    looked: list[str] = []
    real = socket.getaddrinfo

    def wrapped(host: str, *args: object, **kwargs: object) -> object:
        looked.append(host)
        return real(host, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(socket, "getaddrinfo", wrapped)
    code, findings, benchmark = _scan(tmp_path, monkeypatch, redirect_app(_vulnerable))
    found = [item for item in findings if item["attack"] == "web.open_redirect"]
    assert code == 1
    assert benchmark["execution_status"] == "complete"
    assert found
    assert found[0]["engine"] == "insidia"
    assert "302 Location:" in str(found[0]["response"])
    assert _HOST in str(found[0]["response"])
    assert _HOST not in looked
    assert "CWE-601" in str(found[0]["remediation"])
    assert not any("returned HTTP 404" in skip for skip in benchmark["skips"])


def test_meta_refresh_is_an_open_redirect(
    redirect_app: Callable[[Reply], int],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    code, findings, benchmark = _scan(tmp_path, monkeypatch, redirect_app(_meta))
    found = [item for item in findings if item["attack"] == "web.open_redirect"]
    assert code == 1
    assert benchmark["execution_status"] == "complete"
    assert found
    assert "client redirect" in str(found[0]["response"])


def test_relative_redirects_are_clean(
    redirect_app: Callable[[Reply], int],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    code, findings, benchmark = _scan(tmp_path, monkeypatch, redirect_app(_relative_only))
    assert code == 0
    assert benchmark["execution_status"] == "complete"
    assert [item for item in findings if item["attack"] == "web.open_redirect"] == []
