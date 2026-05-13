# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2020 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.


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
