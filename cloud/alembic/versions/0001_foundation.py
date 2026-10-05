"""Apply the Phase 0 foundation schema."""

from pathlib import Path

from alembic import op

revision = "0001_foundation"
down_revision = None
branch_labels = None
depends_on = None

_SQL = Path(__file__).resolve().parents[3] / "schema" / "migrations" / "0001_foundation.sql"


def upgrade() -> None:
    op.get_bind().exec_driver_sql(_SQL.read_text())


def downgrade() -> None:
    raise RuntimeError("the foundation migration is irreversible")
