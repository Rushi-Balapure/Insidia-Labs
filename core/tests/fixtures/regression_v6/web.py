"""Vulnerable web app from the N2 cases.

SSTI-style ``{{a*b}}`` rendering, command injection on ``/ping``, path
traversal on ``/file``, and an id lookup on ``/api/users/<id>``. The QA script shelled
out and opened ``/workspace/insidia-qa/targets/files``. This copy keeps that
behavior on POSIX, binds only 127.0.0.1, and records request lines in memory.
A missing traversed file falls back to a bundled passwd or win.ini body so the
same probes still return file contents on a host without those paths.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

from tests.fixtures.regression_v6.server import RecordingServer, note_request, send_text

_FILES = Path(__file__).resolve().parent / "files"
_PASSWD = "root:x:0:0:root:/root:/bin/bash\napp:x:1000:1000::/home/app:/bin/sh\n"
_WIN_INI = "[fonts]\n[extensions]\n"
_USERS = {
    "1": {"id": 1, "email": "a@x", "ssn": "111"},
    "2": {"id": 2, "email": "b@x", "ssn": "222"},
}


def render_hello(name: str) -> str:
    """Render ``{{n*m}}`` the way the QA ``/hello`` handler did."""

    def repl(match: re.Match[str]) -> str:
        factors = re.fullmatch(r"(\d+)\s*\*\s*(\d+)", match.group(1))
        if factors is None:
            return match.group(0)
        return str(int(factors.group(1)) * int(factors.group(2)))

    rendered = re.sub(r"\{\{(.+?)\}\}", repl, name)
    return f"<h1>Hello {rendered}</h1>"


def ping(host: str) -> str:
    """Output of ``echo pinging <host>`` through a shell, which is the bug."""
    if os.name != "posix":
        return _ping_simulated(host)
    try:
        completed = subprocess.run(
            "echo pinging " + host,
            shell=True,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return "ping timed out"
    return completed.stdout


def _ping_simulated(host: str) -> str:
    """Same observable output as the POSIX shell for the scanner's payloads."""
    text = f"pinging {host}"
    if any(mark in host for mark in (";", "&&", "|", "$(", "`")):
        text += "\nuid=1000(app) gid=1000(app) groups=1000(app)"
    return text.replace("insidia$((6*7))cmdi", "insidia42cmdi")


def read_file(name: str) -> str:
    """Join ``name`` onto the files directory with no containment check."""
    try:
        return (_FILES / name).read_text(encoding="utf-8", errors="replace")
    except OSError:
        folded = name.replace("\\", "/").lower()
        if "passwd" in folded:
            return _PASSWD
        if "win.ini" in folded:
            return _WIN_INI
        raise


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        note_request(self)
        parsed = urlparse(self.path)
        query = dict(parse_qsl(parsed.query))
        path = parsed.path
        if path == "/":
            send_text(
                self,
                200,
                '<a href="/hello?name=x">hello</a> <a href="/ping?host=127.0.0.1">ping</a>',
                "text/html",
            )
            return
        if path == "/hello":
            send_text(self, 200, render_hello(query.get("name", "")), "text/html")
            return
        if path == "/ping":
            send_text(self, 200, ping(query.get("host", "")), "text/plain")
            return
        if path == "/file":
            try:
                body = read_file(query.get("name", ""))
            except OSError as exc:
                send_text(self, 404, str(exc), "text/plain")
                return
            send_text(self, 200, body, "text/plain")
            return
        if path.startswith("/api/users/"):
            user = _USERS.get(path.rsplit("/", 1)[1])
            if user is None:
                send_text(self, 404, "null", "application/json")
                return
            send_text(self, 200, json.dumps(user), "application/json")
            return
        send_text(self, 404, "nf", "text/plain")


def start() -> RecordingServer:
    return RecordingServer(Handler)


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8090
    RecordingServer(Handler, port).serve_forever()


if __name__ == "__main__":
    main()
