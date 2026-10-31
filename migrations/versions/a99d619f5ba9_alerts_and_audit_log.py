"""alerts and audit_log

Revision ID: a99d619f5ba9
Revises:
Create Date: 2026-10-31 10:41:23.460618

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a99d619f5ba9'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE alerts (
      alert_id         uuid PRIMARY KEY,
      source_ref       text,
      source_system    text NOT NULL,
      alert_type       text NOT NULL,
      fingerprint      text NOT NULL,
      received_at      timestamptz NOT NULL,
      first_seen       timestamptz NOT NULL DEFAULT now(),
      last_seen        timestamptz NOT NULL DEFAULT now(),
      occurrence_count integer NOT NULL DEFAULT 1,
      status           text NOT NULL DEFAULT 'new',
      doc              jsonb NOT NULL
    );
    CREATE INDEX ix_alerts_fp_last ON alerts (fingerprint, last_seen DESC);
    CREATE INDEX ix_alerts_type ON alerts (alert_type);

    CREATE TABLE audit_log (
      id             bigserial PRIMARY KEY,
      ts             timestamptz NOT NULL,
      correlation_id uuid NOT NULL,
      stage          text NOT NULL,
      event          text NOT NULL,
      actor          text NOT NULL DEFAULT 'system',
      payload        jsonb NOT NULL DEFAULT '{}',
      prev_hash      char(64) NOT NULL,
      row_hash       char(64) NOT NULL
    );
    CREATE INDEX ix_audit_corr ON audit_log (correlation_id, ts);
    """)


def downgrade() -> None:
    op.execute("DROP TABLE audit_log; DROP TABLE alerts;")
