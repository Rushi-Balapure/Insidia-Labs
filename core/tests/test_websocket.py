import json
import socket
import threading
from pathlib import Path

from insidia.cli import main

CANARY = "insidia-plant-canary-7f3a"


def test_websocket_chat_leak_is_a_finding(tmp_path: Path) -> None:
    seen: dict[str, str] = {}
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve() -> None:
        connection, _ = listener.accept()
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                data += connection.recv(4096)
            connection.sendall(b"HTTP/1.1 101 Switching Protocols\r\n\r\n")
            seen["payload"] = _read_client_text(connection)
            body = CANARY.encode()
            connection.sendall(bytes([0x81, len(body)]) + body)
        finally:
            connection.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    config = tmp_path / "insidia.yaml"
    config.write_text(
        f"""
version: 1
policy: L1
coverage: standard
scope:
  - host: 127.0.0.1
targets:
  socket-chat:
    kind: chat
    url: ws://127.0.0.1:{port}/chat
    rate_limit:
      rps: 100
      concurrency: 1
"""
    )
    try:
        assert main(["scan", "--config", str(config)]) == 1
    finally:
        listener.close()
        thread.join(timeout=5)
    assert seen["payload"] == "secret"
    findings = json.loads(_findings(tmp_path).read_text())
    assert findings[0]["attack"] == "ai.data_leakage"
    assert findings[0]["engine"] == "insidia"


def _read_client_text(connection: socket.socket) -> str:
    header = _read_exact(connection, 2)
    length = header[1] & 0x7F
    mask = _read_exact(connection, 4)
    payload = _read_exact(connection, length)
    return bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload)).decode()


def _read_exact(connection: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            break
        data += chunk
    return data


def _findings(root: Path) -> Path:
    runs = sorted((root / ".insidia" / "runs").iterdir())
    return runs[-1] / "findings.json"
