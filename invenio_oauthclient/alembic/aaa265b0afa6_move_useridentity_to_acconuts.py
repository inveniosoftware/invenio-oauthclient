#
# This file is part of Invenio.
# Copyright (C) 2016-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Move UserIdentity to accounts."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "aaa265b0afa6"
down_revision = "bff1f190b9bd"
branch_labels = ()
depends_on = "62efc52773d4"


def upgrade():
    """Upgrade database."""
    op.execute(
        "INSERT INTO accounts_useridentity "
        "(id, method, id_user, created, updated) "
        "SELECT id, method, id_user, created, updated "
        "FROM oauthclient_useridentity;"
    )
    op.drop_table("oauthclient_useridentity")


def downgrade():
    """Downgrade database."""
    op.create_table(
        "oauthclient_useridentity",
        sa.Column("created", sa.DateTime(), nullable=False),
        sa.Column("updated", sa.DateTime(), nullable=False),
        sa.Column("id", sa.String(length=255), nullable=False),
        sa.Column("method", sa.String(length=255), nullable=False),
        sa.Column("id_user", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["id_user"],
            ["accounts_user.id"],
            name=op.f("fk_oauthclient_useridentity_id_user_accounts_user"),
        ),
        sa.PrimaryKeyConstraint(
            "id", "method", name=op.f("pk_oauthclient_useridentity")
        ),
    )
    op.create_index(
        "useridentity_id_user_method",
        "oauthclient_useridentity",
        ["id_user", "method"],
        unique=True,
    )
    op.execute(
        "INSERT INTO oauthclient_useridentity "
        "(id, method, id_user, created, updated) "
        "SELECT id, method, id_user, created, updated "
        "FROM accounts_useridentity;"
    )
