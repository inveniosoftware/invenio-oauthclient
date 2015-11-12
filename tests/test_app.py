# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2014, 2015 CERN.
#
# Invenio is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# Invenio is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Invenio; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.

"""Test helpers."""

from __future__ import absolute_import

import os

from invenio_db import InvenioDB, db

from invenio_oauthclient import InvenioOAuthClient

from flask import Flask

from flask_cli import FlaskCLI


def test_version():
    """Test version import."""
    from invenio_oauthclient import __version__
    assert __version__


def test_init():
    """Test extension initialization."""
    app = Flask('testapp')
    FlaskCLI(app)
    ext = InvenioOAuthClient(app)
    assert 'invenio-oauthclient' in app.extensions

    app = Flask('testapp')
    FlaskCLI(app)
    ext = InvenioOAuthClient()
    assert 'invenio-oauthclient' not in app.extensions
    ext.init_app(app)
    assert 'invenio-oauthclient' in app.extensions


def test_db(request):
    """Test database backend."""
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
        'SQLALCHEMY_DATABASE_URI', 'sqlite://'
    )
    FlaskCLI(app)
    InvenioDB(app)
    InvenioOAuthClient(app)

    def teardown():
        with app.app_context():
            db.drop_all()

    request.addfinalizer(teardown)

    with app.app_context():
        db.create_all()
        tables = list(filter(lambda table: table.startswith('oauthclient'),
                             db.metadata.tables.keys()))
        assert len(tables) == 3
