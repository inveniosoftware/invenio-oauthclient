# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2016-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Create oauthclient branch."""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "44ab9963e8cf"
down_revision = "dbdbc1b19cf2"
branch_labels = ("invenio_oauthclient",)
depends_on = "dbdbc1b19cf2"


def upgrade():
    """Upgrade database."""
    pass


def downgrade():
    """Downgrade database."""
    pass
