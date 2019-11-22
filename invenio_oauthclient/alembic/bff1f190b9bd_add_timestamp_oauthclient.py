# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2016-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Add Timestamp to oauthclient tables."""

from datetime import datetime

import sqlalchemy as sa
from alembic import op
from sqlalchemy.sql import text

# revision identifiers, used by Alembic.
revision = 'bff1f190b9bd'
down_revision = '97bbc733896c'
branch_labels = ()
depends_on = None


def upgrade():
    """Upgrade database."""
    current_date = datetime.utcnow()

    # Add 'created' and 'updated' columns to RemoteAccount
    _add_created_updated_columns('oauthclient_remoteaccount', current_date)

    # Add 'created' and 'updated' columns to RemoteToken
    _add_created_updated_columns('oauthclient_remotetoken', current_date)

    # Add 'created' and 'updated' columns to UserIdentity
    _add_created_updated_columns('oauthclient_useridentity', current_date)


def downgrade():
    """Downgrade database."""
    # Remove 'created' and 'updated' columns
    op.drop_column('oauthclient_remoteaccount', 'created')
    op.drop_column('oauthclient_remoteaccount', 'updated')

    op.drop_column('oauthclient_remotetoken', 'created')
    op.drop_column('oauthclient_remotetoken', 'updated')

    op.drop_column('oauthclient_useridentity', 'created')
    op.drop_column('oauthclient_useridentity', 'updated')


def _add_created_updated_columns(table, date):

    params = {'date': date}

    op.add_column(
        table,
        sa.Column('created', sa.DateTime()))
    op.add_column(
        table,
        sa.Column('updated', sa.DateTime()))

    op.execute(text('UPDATE ' + table + ' SET created= :date')
               .bindparams(date=date), params)
    op.execute(text('UPDATE ' + table + ' SET updated= :date')
               .bindparams(date=date), params)

    op.alter_column(table, 'created',
                    existing_type=sa.DateTime,
                    nullable=False)
    op.alter_column(table, 'updated',
                    existing_type=sa.DateTime,
                    nullable=False)
