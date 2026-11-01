"""decisions cases

Revision ID: 6eb513fb505f
Revises: a99d619f5ba9
Create Date: 2026-11-01 12:21:03.588486

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "6eb513fb505f"
down_revision: Union[str, Sequence[str], None] = "a99d619f5ba9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE decisions (
      id           bigserial PRIMARY KEY,
      alert_id     uuid NOT NULL REFERENCES alerts(alert_id),
      verdict      text NOT NULL,
      severity_id  smallint NOT NULL,
      priority     text NOT NULL,
      action       text NOT NULL,
      rule_id      text NOT NULL,
      rule_version text NOT NULL,
      reasons      jsonb NOT NULL,
      shadow       boolean NOT NULL DEFAULT false,
      decided_at   timestamptz NOT NULL
    );
    CREATE INDEX ix_decisions_alert ON decisions (alert_id);
    CREATE TABLE cases (
      alert_id    uuid PRIMARY KEY REFERENCES alerts(alert_id),
      fingerprint text NOT NULL,
      backend     text NOT NULL,
      case_id     text NOT NULL,
      case_url    text NOT NULL,
      created_at  timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX ix_cases_fp ON cases (fingerprint, created_at DESC);
    CREATE INDEX ix_cases_case ON cases (case_id);
    -- audit_log yalnız əlavə olunur: UPDATE və DELETE qadağandır
    CREATE FUNCTION audit_log_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      RAISE EXCEPTION 'audit_log append-only: % qadağandır', TG_OP;
    END $$;
    CREATE TRIGGER audit_log_no_change BEFORE UPDATE OR DELETE ON audit_log
      FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();
    """)


def downgrade() -> None:
    op.execute("""
    DROP TRIGGER audit_log_no_change ON audit_log;
    DROP FUNCTION audit_log_immutable();
    DROP TABLE cases; DROP TABLE decisions;
    """)
