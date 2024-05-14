#
# This file is part of Invenio.
# Copyright (C) 2016-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Add expires_at and refresh_token to remote token."""

import sqlalchemy as sa
import sqlalchemy_utils
from alembic import op

# revision identifiers, used by Alembic.
revision = "7def990b852e"
down_revision = "aaa265b0afa6"
branch_labels = ()
depends_on = ("aaa265b0afa6",)


def upgrade():
    """Upgrade database."""
    op.add_column(
        "oauthclient_remotetoken",
        sa.Column("refresh_token", sqlalchemy_utils.EncryptedType(), nullable=True),
    )
    op.add_column(
        "oauthclient_remotetoken", sa.Column("expires_at", sa.DateTime(), nullable=True)
    )


def downgrade():
    """Downgrade database."""
    op.drop_column("oauthclient_remotetoken", "expires_at")
    op.drop_column("oauthclient_remotetoken", "refresh_token")
