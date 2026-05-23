# SPDX-FileCopyrightText: 2016-2025 CERN.
# SPDX-FileCopyrightText: 2026 Graz University of Technology.
# SPDX-License-Identifier: MIT

"""Alter datetime columns to utc aware datetime columns."""

from invenio_db.utils import (
    update_table_columns_column_type_to_datetime,
    update_table_columns_column_type_to_utc_datetime,
)

# revision identifiers, used by Alembic.
revision = "edf0c0907f40"
down_revision = "7def990b852e"
branch_labels = ()
depends_on = None


def upgrade():
    """Upgrade database."""
    for table_name in ["oauthclient_remoteaccount", "oauthclient_remotetoken"]:
        update_table_columns_column_type_to_utc_datetime(table_name, "created")
        update_table_columns_column_type_to_utc_datetime(table_name, "updated")
    update_table_columns_column_type_to_utc_datetime(
        "oauthclient_remotetoken", "expires"
    )


def downgrade():
    """Downgrade database."""
    for table_name in ["oauthclient_remoteaccount", "oauthclient_remotetoken"]:
        update_table_columns_column_type_to_datetime(table_name, "created")
        update_table_columns_column_type_to_datetime(table_name, "updated")
    update_table_columns_column_type_to_datetime("oauthclient_remotetoken", "expires")
