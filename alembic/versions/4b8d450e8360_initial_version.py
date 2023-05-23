"""Initial version

Revision ID: 4b8d450e8360
Revises: 
Create Date: 2023-05-10 16:04:43.893667

"""
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "4b8d450e8360"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        "rstuf_target_roles",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("rolename", sa.String(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("last_update", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_rstuf_target_roles_id"),
        "rstuf_target_roles",
        ["id"],
        unique=False,
    )
    op.create_table(
        "rstuf_target_files",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("path", sa.String(), nullable=False),
        sa.Column(
            "info", postgresql.JSON(astext_type=sa.Text()), nullable=False
        ),
        sa.Column("published", sa.Boolean(), nullable=False),
        sa.Column(
            "action",
            sa.Enum("ADD", "REMOVE", name="targetaction"),
            nullable=False,
        ),
        sa.Column("last_update", sa.DateTime(), nullable=True),
        sa.Column("targets_role", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(
            ["targets_role"],
            ["rstuf_target_roles.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_rstuf_target_files_id"),
        "rstuf_target_files",
        ["id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_rstuf_target_files_path"),
        "rstuf_target_files",
        ["path"],
        unique=True,
    )
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(
        op.f("ix_rstuf_target_files_path"), table_name="rstuf_target_files"
    )
    op.drop_index(
        op.f("ix_rstuf_target_files_id"), table_name="rstuf_target_files"
    )
    op.drop_table("rstuf_target_files")
    op.drop_index(
        op.f("ix_rstuf_target_roles_id"), table_name="rstuf_target_roles"
    )
    op.drop_table("rstuf_target_roles")
    # ### end Alembic commands ###