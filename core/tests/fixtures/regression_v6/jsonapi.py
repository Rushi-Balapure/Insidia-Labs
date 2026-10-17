"""LedgerAPI dummy. Safe mode parameterizes search and rejects non-alphanumeric q.

The QA script stored sqlite under /tmp and logged to /workspace/insidia-qa.
This copy uses a fresh database next to the server object, binds 127.0.0.1,
and records request lines in memory. The N2 negative case uses safe ``search``.
"""

from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
import urllib.parse
from http.server import BaseHTTPRequestHandler
from pathlib import Path

from tests.fixtures.regression_v6.server import RecordingServer, note_request, send_bytes

_ROWS = (
    (1, "Ada Lovelace", "ada@zentrix.example", "111-22-3333", 1200.5),
    (2, "Alan Turing", "alan@zentrix.example", "444-55-6666", 980.0),
    (3, "Grace Hopper", "grace@zentrix.example", "777-88-9999", 2500.25),
)


def _seed(path: Path) -> None:
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE accounts ("
        "id INTEGER PRIMARY KEY, name TEXT, email TEXT, ssn TEXT, balance REAL)"
    )
    connection.executemany("INSERT INTO accounts VALUES (?,?,?,?,?)", _ROWS)
    connection.commit()
    connection.close()


class Handler(BaseHTTPRequestHandler):
    mode = "safe"
    database = ""

    def log_message(self, fmt: str, *args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        note_request(self)
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        path = parsed.path.rstrip("/") or "/"
        if path == "/v1/accounts" and "q" in query:
            self._search(query["q"][0])
            return
        if path.startswith("/v1/accounts/"):
            self._get_one(path.split("/")[-1])
            return
        if path == "/v1/go":
            self._go(query.get("next", ["/"])[0])
            return
        if path == "/healthz":
            self._json(200, {"ok": True})
            return
        self.send_error(404)

    def _json(self, status: int, payload: object) -> None:
        send_bytes(self, status, json.dumps(payload).encode(), "application/json")

    def _search(self, text: str) -> None:
        connection = sqlite3.connect(self.database)
        if self.mode == "safe":
            if not text.isalnum():
                connection.close()
                self._json(400, {"error": "q must be alphanumeric"})
                return
            rows = connection.execute(
                "SELECT id, name, email FROM accounts WHERE name LIKE ?",
                (f"%{text}%",),
            ).fetchall()
            keys = ("id", "name", "email")
        else:
            try:
                rows = connection.execute(
                    "SELECT id, name, email, ssn, balance FROM accounts "
                    f"WHERE name LIKE '%{text}%'"
                ).fetchall()
            except sqlite3.Error as exc:
                connection.close()
                self._json(500, {"error": str(exc), "query": text})
                return
            keys = ("id", "name", "email", "ssn", "balance")
        connection.close()
        self._json(200, {"results": [dict(zip(keys, row, strict=True)) for row in rows]})

    def _get_one(self, account_id: str) -> None:
        connection = sqlite3.connect(self.database)
        row = connection.execute(
            "SELECT id, name, email, ssn, balance FROM accounts WHERE id=?",
            (account_id,),
        ).fetchone()
        connection.close()
        if row is None:
            self._json(404, {"error": "missing"})
            return
        if self.mode == "safe":
            user = self.headers.get("X-User-Id")
            if user != str(row[0]):
                self._json(403, {"error": "forbidden"})
                return
            self._json(200, {"id": row[0], "name": row[1], "email": row[2]})
            return
        self._json(
            200,
            {"id": row[0], "name": row[1], "email": row[2], "ssn": row[3], "balance": row[4]},
        )

    def _go(self, nxt: str) -> None:
        if self.mode == "safe" and not (
            nxt.startswith("/v1/") and "://" not in nxt and "\\" not in nxt
        ):
            self._json(400, {"error": "next must be a relative /v1/ path"})
            return
        self.send_response(302)
        self.send_header("Location", nxt)
        self.end_headers()


class LedgerServer(RecordingServer):
    def __init__(self, handler: type[BaseHTTPRequestHandler], port: int, database: Path) -> None:
        super().__init__(handler, port)
        self.database_path = database


def start(mode: str, port: int = 0) -> LedgerServer:
    if mode not in {"vuln", "safe"}:
        raise ValueError(f"ledger mode must be vuln or safe, got {mode}")
    directory = tempfile.mkdtemp(prefix=f"ledger-{mode}-")
    database = Path(directory) / "ledger.sqlite3"
    _seed(database)

    class Bound(Handler):
        pass

    Bound.mode = mode
    Bound.database = str(database)
    return LedgerServer(Bound, port, database)


def main() -> None:
    port = int(sys.argv[1])
    mode = sys.argv[2]
    start(mode, port).serve_forever()


if __name__ == "__main__":
    main()
