# SPDX-FileCopyrightText: 2016-2025 CERN.
# SPDX-License-Identifier: MIT

"""Extra Data JSONB."""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "1758275763"
down_revision = "aaa265b0afa6"
branch_labels = ()
depends_on = None


def upgrade():
    """Upgrade database."""
    if op.get_context().dialect.name == "postgresql":
        op.alter_column(
            "oauthclient_remoteaccount",
            "extra_data",
            type_=sa.dialects.postgresql.JSONB,
            postgresql_using="extra_data::text::jsonb",
        )


def downgrade():
    """Downgrade database."""
    if op.get_context().dialect.name == "postgresql":
        op.alter_column(
            "oauthclient_remoteaccount",
            "extra_data",
            type_=sa.dialects.postgresql.JSON,
            postgresql_using="extra_data::text::json",
        )
