# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2016-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Create oauthclient tables."""

import sqlalchemy as sa
import sqlalchemy_utils
from alembic import op
from sqlalchemy.engine.reflection import Inspector

# revision identifiers, used by Alembic.
revision = '97bbc733896c'
down_revision = '44ab9963e8cf'
branch_labels = ()
depends_on = '9848d0149abd'


def upgrade():
    """Upgrade database."""
    op.create_table(
        'oauthclient_remoteaccount',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('client_id', sa.String(length=255), nullable=False),
        sa.Column(
            'extra_data',
            sqlalchemy_utils.JSONType(),
            nullable=False),
        sa.ForeignKeyConstraint(['user_id'], [u'accounts_user.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'client_id')
    )
    op.create_table(
        'oauthclient_useridentity',
        sa.Column('id', sa.String(length=255), nullable=False),
        sa.Column('method', sa.String(length=255), nullable=False),
        sa.Column('id_user', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['id_user'], [u'accounts_user.id'], ),
        sa.PrimaryKeyConstraint('id', 'method')
    )
    op.create_index(
        'useridentity_id_user_method', 'oauthclient_useridentity',
        ['id_user', 'method'], unique=True
    )
    op.create_table(
        'oauthclient_remotetoken',
        sa.Column('id_remote_account', sa.Integer(), nullable=False),
        sa.Column('token_type', sa.String(length=40), nullable=False),
        sa.Column(
            'access_token',
            sqlalchemy_utils.EncryptedType(),
            nullable=False),
        sa.Column('secret', sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(
            ['id_remote_account'], [u'oauthclient_remoteaccount.id'],
            name='fk_oauthclient_remote_token_remote_account'
        ),
        sa.PrimaryKeyConstraint('id_remote_account', 'token_type')
    )


def downgrade():
    """Downgrade database."""
    ctx = op.get_context()
    insp = Inspector.from_engine(ctx.connection.engine)

    op.drop_table('oauthclient_remotetoken')

    for fk in insp.get_foreign_keys('oauthclient_useridentity'):
        if fk['referred_table'] == 'accounts_user':
            op.drop_constraint(
                op.f(fk['name']),
                'oauthclient_useridentity',
                type_='foreignkey'
            )

    op.drop_index(
        'useridentity_id_user_method',
        table_name='oauthclient_useridentity')
    op.drop_table('oauthclient_useridentity')
    op.drop_table('oauthclient_remoteaccount')
