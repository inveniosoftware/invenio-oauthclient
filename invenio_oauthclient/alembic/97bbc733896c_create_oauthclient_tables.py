#
# This file is part of Invenio.
# Copyright (C) 2016 CERN.
#
# Invenio is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# Invenio is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Invenio; if not, write to the
# Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston,
# MA 02111-1307, USA.
#
# In applying this license, CERN does not
# waive the privileges and immunities granted to it by virtue of its status
# as an Intergovernmental Organization or submit itself to any jurisdiction.

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
            sqlalchemy_utils.types.json.JSONType(),
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
            sqlalchemy_utils.types.encrypted.EncryptedType(),
            nullable=False),
        sa.Column('secret', sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(
            ['id_remote_account'], [u'oauthclient_remoteaccount.id'],
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
