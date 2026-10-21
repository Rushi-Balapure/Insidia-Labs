"""Loopback HTTP server shared by the N2 and N4 dummy targets.

Every fixture binds ``127.0.0.1`` and an ephemeral port. Request lines are kept
on the server so a test can see what the scan actually sent.
"""

from __future__ import annotations

import shutil
import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOST = "127.0.0.1"


class RecordingServer(ThreadingHTTPServer):
    """HTTP server bound to 127.0.0.1 that records each request line."""

    def __init__(self, handler: type[BaseHTTPRequestHandler], port: int = 0) -> None:
        super().__init__((HOST, port), handler)
        bound = self.server_address[0]
        if bound != HOST:
            raise RuntimeError(f"fixture bound {bound}, expected {HOST}")
        self.requests: list[tuple[float, str]] = []
        self._lock = threading.Lock()

    def note(self, requestline: str) -> None:
        with self._lock:
            self.requests.append((time.monotonic(), requestline))

    @property
    def port(self) -> int:
        return int(self.server_address[1])


def note_request(handler: BaseHTTPRequestHandler) -> None:
    server = handler.server
    if isinstance(server, RecordingServer):
        server.note(handler.requestline)


def send_bytes(
    handler: BaseHTTPRequestHandler, status: int, body: bytes, content_type: str
) -> None:
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def send_text(
    handler: BaseHTTPRequestHandler, status: int, body: str, content_type: str
) -> None:
    send_bytes(handler, status, body.encode(), content_type)


def wait_until_listening(port: int) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.01)
    raise AssertionError(f"fixture did not listen on {HOST}:{port}")


@contextmanager
def serve(server: RecordingServer) -> Iterator[RecordingServer]:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        wait_until_listening(server.port)
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        database = getattr(server, "database_path", None)
        if isinstance(database, Path):
            shutil.rmtree(database.parent, ignore_errors=True)
