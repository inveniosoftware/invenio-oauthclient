# SPDX-FileCopyrightText: 2015-2020 CERN.
# SPDX-License-Identifier: MIT

"""Alembic upgrade tests."""

import pytest
from invenio_db import db


def test_alembic(app):
    """Test alembic recipes."""
    ext = app.extensions["invenio-db"]

    with app.app_context():
        if db.engine.name == "sqlite":
            raise pytest.skip("Upgrades are not supported on SQLite.")

        assert not ext.alembic.compare_metadata()
        db.drop_all()
        ext.alembic.upgrade()

        assert not ext.alembic.compare_metadata()
        ext.alembic.downgrade(target="44ab9963e8cf")
        ext.alembic.upgrade()

        assert not ext.alembic.compare_metadata()
        ext.alembic.downgrade(target="44ab9963e8cf")
