"""feedback links

Revision ID: 11e8c8fe1ed5
Revises: 6eb513fb505f
Create Date: 2026-11-03 06:28:09

"""

from typing import Sequence, Union

from alembic import op

revision: str = "11e8c8fe1ed5"
down_revision: Union[str, None] = "6eb513fb505f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE feedback (
      id             bigserial PRIMARY KEY,
      alert_id       uuid NOT NULL REFERENCES alerts(alert_id),
      source         text NOT NULL,
      analyst        text NOT NULL,
      auto_verdict   text NOT NULL,
      human_verdict  text NOT NULL,
      auto_severity  smallint,
      human_severity smallint,
      rule_id        text NOT NULL,
      rule_version   text NOT NULL,
      comment        text NOT NULL DEFAULT '',
      created_at     timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX ix_feedback_rule ON feedback (rule_id, rule_version);

    CREATE TABLE case_links (
      alert_id        uuid NOT NULL REFERENCES alerts(alert_id),
      case_id         text NOT NULL,
      related_case_id text NOT NULL,
      created_at      timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY (case_id, related_case_id)
    );
    """)


def downgrade() -> None:
    op.execute("DROP TABLE case_links; DROP TABLE feedback;")
