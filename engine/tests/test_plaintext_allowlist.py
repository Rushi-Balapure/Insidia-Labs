"""The foundation schema keeps customer text out of plaintext columns."""

from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parents[2]
_SQL = (_ROOT / "schema" / "migrations" / "0001_foundation.sql").read_text()
_ALLOW = yaml.safe_load((_ROOT / "schema" / "plaintext_allowlist.yaml").read_text())


def _tables(sql: str) -> dict[str, list[tuple[str, str]]]:
    tables: dict[str, list[tuple[str, str]]] = {}
    current: str | None = None
    for raw in sql.splitlines():
        line = raw.split("--", 1)[0].strip().rstrip(",")
        if not line or line.startswith("DO"):
            continue
        upper = line.upper()
        if upper.startswith("CREATE TABLE"):
            current = line.split()[2]
            tables[current] = []
            continue
        if current and line.startswith(")"):
            current = None
            continue
        if current is None or line.upper().startswith(
            ("PRIMARY", "CONSTRAINT", "CHECK", "UNIQUE", "FOREIGN")
        ):
            continue
        if current:
            parts = line.split()
            if len(parts) >= 2:
                tables[current].append((parts[0], parts[1].lower()))
    return tables


def test_text_columns_are_encrypted_or_allowlisted() -> None:
    allowed = {(item["table"], item["column"]) for item in _ALLOW["columns"]}
    text_types = {"text", "citext", "varchar", "json", "jsonb"}
    for table, columns in _tables(_SQL).items():
        for name, kind in columns:
            if kind not in text_types:
                continue
            assert name.endswith("_enc") or (table, name) in allowed, (table, name)


def test_audit_table_rejects_mutation_in_sql() -> None:
    assert "audit_events is append-only" in _SQL
    assert "BEFORE UPDATE OR DELETE ON audit_events" in _SQL
    assert "FORCE ROW LEVEL SECURITY" in _SQL
    assert "NOBYPASSRLS" in _SQL
