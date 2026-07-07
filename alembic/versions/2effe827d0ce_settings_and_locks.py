"""settings and locks
 
Revision ID: 2effe827d0ce
Revises: 1effe827d0cd
Create Date: 2026-04-18 12:00:00.000000
 
"""
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from alembic import op
 
# revision identifiers, used by Alembic.
revision = "2effe827d0ce"
down_revision = "1effe827d0cd"
branch_labels = None
depends_on = None
 
 
def upgrade() -> None:
    op.create_table(
        "rstuf_settings",
        sa.Column("key", sa.String(), nullable=False),
        sa.Column(
            "value", postgresql.JSON(astext_type=sa.Text()), nullable=False
        ),
        sa.PrimaryKeyConstraint("key"),
    )
    op.create_index(
        op.f("ix_rstuf_settings_key"),
        "rstuf_settings",
        ["key"],
        unique=False,
    )
    op.create_table(
        "rstuf_locks",
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("expires", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("name"),
    )
    op.create_index(
        op.f("ix_rstuf_locks_name"),
        "rstuf_locks",
        ["name"],
        unique=False,
    )
 
 
def downgrade() -> None:
    op.drop_index(op.f("ix_rstuf_locks_name"), table_name="rstuf_locks")
    op.drop_table("rstuf_locks")
    op.drop_index(op.f("ix_rstuf_settings_key"), table_name="rstuf_settings")
    op.drop_table("rstuf_settings")
