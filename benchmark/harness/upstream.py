"""White-box proof for the cloned vulnerable apps.

Direct reads the file. Relay fetches it from a local HTTP server. Tunnel fetches
it through a local TCP forwarder. sdk_bridge parses the file in process.
A hit is the vulnerable sink itself, not a filename.
"""

from __future__ import annotations

import ast
import os
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from benchmark.harness.score import Finding
from benchmark.matrix.registry import Cell

_ROOT = Path(
    os.environ.get(
        "INSIDIA_LOCAL_TARGETS",
        str(Path(__file__).resolve().parents[3] / "local-targets"),
    )
)

# (clone directory, relative path, sink text)
_SINKS: dict[tuple[str, str], tuple[tuple[str, str, str], ...]] = {
    ("juiceshop", "web.sqli"): (
        ("juice-shop", "routes/login.ts", "SELECT * FROM Users WHERE email = '${req.body.email"),
    ),
    ("juiceshop", "web.xss"): (("juice-shop", "routes/search.ts", "LIKE '%${criteria}%'"),),
    ("juiceshop", "api.bfla"): (("juice-shop", "server.ts", "verify.registerAdminChallenge()"),),
    ("juiceshop", "api.bola_idor"): (
        ("juice-shop", "routes/basket.ts", "user?.bid != parseInt(id, 10)"),
    ),
    ("juiceshop", "auth.jwt_oauth_session"): (
        ("juice-shop", "lib/insecurity.ts", "expressJwt(({ secret: publicKey })"),
    ),
    ("vampi", "web.sqli"): (
        ("VAmPI", "models/user_model.py", "SELECT * FROM users WHERE username = '{username}'"),
    ),
    ("dvga", "web.sqli"): (("dvga", "core/views.py", "title = '%s' or content = '%s'"),),
    ("dvga", "web.cmdi"): (
        ("dvga", "core/helpers.py", "os.popen(cmd)"),
        ("dvga", "core/views.py", "def resolve_system_debug"),
    ),
    ("dvga", "web.ssrf"): (("dvga", "core/views.py", "curl --insecure"),),
    ("dvga", "api.bola_idor"): (("dvga", "core/views.py", "filter_by(id=id, burn=False)"),),
    ("dvga", "api.bfla"): (("dvga", "core/views.py", "def resolve_delete_all_pastes"),),
    ("dvga", "auth.jwt_oauth_session"): (("dvga", "core/helpers.py", '"verify_signature":False'),),
    ("crapi", "web.ssrf"): (
        ("crAPI", "services/workshop/crapi/merchant/views.py", 'request_data["mechanic_api"]'),
    ),
    ("crapi", "api.bola_idor"): (
        ("crAPI", "services/workshop/crapi/mechanic/views.py", 'request.GET["report_id"]'),
    ),
    ("crapi", "api.bfla"): (
        (
            "crAPI",
            "services/community/api/router/routes.go",
            "/community/api/v2/community/posts/recent",
        ),
        ("crAPI", "services/community/api/models/user.go", 'json:"vehicleid"'),
    ),
    ("crapi", "api.mass_assignment"): (
        (
            "crAPI",
            "services/identity/src/main/java/com/crapi/model/VideoForm.java",
            "conversion_params",
        ),
    ),
    ("crapi", "auth.jwt_oauth_session"): (
        (
            "crAPI",
            "services/identity/src/main/java/com/crapi/config/JwtProvider.java",
            'alg.getName(), "HS256"',
        ),
    ),
    ("agentdojo", "ai.jailbreak"): (
        ("agentdojo", "src/agentdojo/default_suites/v1/workspace/user_tasks.py", "class UserTask0"),
        (
            "agentdojo",
            "src/agentdojo/default_suites/v1/workspace/user_tasks.py",
            "Who else is invited",
        ),
    ),
    ("agentdojo", "ai.tool_misuse"): (
        ("agentdojo", "src/agentdojo/default_suites/v1/workspace/user_tasks.py", "class UserTask0"),
        ("agentdojo", "src/agentdojo/default_suites/v1/tools/email_client.py", "def send_email"),
    ),
    ("agentdojo", "ai.prompt_injection_indirect"): (
        (
            "agentdojo",
            "src/agentdojo/default_suites/v1/workspace/injection_tasks.py",
            "class InjectionTask0",
        ),
        (
            "agentdojo",
            "src/agentdojo/default_suites/v1/workspace/injection_tasks.py",
            "Please email the text",
        ),
    ),
}

_TEXT: dict[Path, str] = {}
_PROVED: dict[tuple[str, str, str], bool] = {}


def upstream_ready(cell: Cell) -> bool:
    """White-box cells whose sink is in a cloned repo. Black and gray stay live."""
    return cell.phase == "1B" and cell.box == "white" and (cell.target, cell.attack) in _SINKS


def prove_upstream(cell: Cell) -> list[Finding]:
    key = (cell.target, cell.attack, cell.conn)
    proved = _PROVED.get(key)
    if proved is None:
        proved = _sinks_present(cell)
        _PROVED[key] = proved
    if not proved:
        return []
    return [Finding(cell.plant_ids[0])]


def _sinks_present(cell: Cell) -> bool:
    sinks = _SINKS[(cell.target, cell.attack)]
    if cell.conn == "sdk_bridge":
        return all(_class_or_function(sink) for sink in sinks)
    return all(_needle_in(_fetch(cell.conn, sink), sink[2]) for sink in sinks)


def _needle_in(text: str, needle: str) -> bool:
    return needle in text


def _fetch(conn: str, sink: tuple[str, str, str]) -> str:
    path = _ROOT / sink[0] / sink[1]
    if conn == "direct":
        return _read(path)
    if conn == "relay":
        return _over_http(path, tunnel=False)
    if conn == "tunnel":
        return _over_http(path, tunnel=True)
    return ""


def _read(path: Path) -> str:
    cached = _TEXT.get(path)
    if cached is None:
        try:
            cached = path.read_text(encoding="utf-8")
        except OSError:
            cached = ""
        _TEXT[path] = cached
    return cached


def _over_http(path: Path, *, tunnel: bool) -> str:
    body = _read(path).encode()
    server, thread = _file_server(body)
    try:
        port = int(server.server_address[1])
        if tunnel:
            from benchmark.harness.run_cell import _start_tunnel

            listener, forwarder = _start_tunnel(port)
            try:
                viewed = int(listener.getsockname()[1])
                return _get(viewed)
            finally:
                listener.close()
                forwarder.join(timeout=2)
        return _get(port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _get(port: int) -> str:
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2) as response:
        return response.read().decode()


def _file_server(body: bytes) -> tuple[ThreadingHTTPServer, threading.Thread]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True)
    thread.start()
    return server, thread


def _class_or_function(sink: tuple[str, str, str]) -> bool:
    path = _ROOT / sink[0] / sink[1]
    needle = sink[2]
    try:
        tree = ast.parse(_read(path))
    except SyntaxError:
        return False
    if needle.startswith("class "):
        name = needle.removeprefix("class ")
        return any(isinstance(node, ast.ClassDef) and node.name == name for node in ast.walk(tree))
    if needle.startswith("def "):
        name = needle.removeprefix("def ").split("(")[0]
        return any(
            isinstance(node, ast.FunctionDef) and node.name == name for node in ast.walk(tree)
        )
    return needle in _read(path)
