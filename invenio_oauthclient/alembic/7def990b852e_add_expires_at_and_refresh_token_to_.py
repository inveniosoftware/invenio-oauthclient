# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2016-2025 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Add expires and refresh_token to remote token."""

import sqlalchemy as sa
import sqlalchemy_utils
from alembic import op
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = "7def990b852e"
down_revision = "1758275763"
branch_labels = ()
depends_on = None


def upgrade():
    """Upgrade database."""
    op.add_column(
        "oauthclient_remotetoken",
        sa.Column(
            "refresh_token", sqlalchemy_utils.StringEncryptedType(), nullable=True
        ),
    )
    op.add_column(
        "oauthclient_remotetoken",
        # We are using `created` and `updated` so it should be `expires` and not `expires_at`
        sa.Column(
            "expires",
            sa.DateTime().with_variant(mysql.DATETIME(fsp=6), "mysql"),
            nullable=True,
        ),
    )


def downgrade():
    """Downgrade database."""
    op.drop_column("oauthclient_remotetoken", "expires")
    op.drop_column("oauthclient_remotetoken", "refresh_token")
