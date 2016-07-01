# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015, 2016 CERN.
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
from copy import deepcopy

from flask import Flask
from flask_cli import FlaskCLI
from flask_oauthlib.client import OAuth as FlaskOAuth
from flask_oauthlib.client import OAuthRemoteApp
from invenio_db import InvenioDB, db
from sqlalchemy_utils.functions import create_database, database_exists

from invenio_oauthclient import InvenioOAuthClient
from invenio_oauthclient.contrib.orcid import REMOTE_APP


def test_version():
    """Test version import."""
    from invenio_oauthclient import __version__
    assert __version__


def test_init():
    """Test extension initialization."""
    app = Flask('testapp')
    FlaskCLI(app)
    FlaskOAuth(app)
    ext = InvenioOAuthClient(app)
    assert 'invenio-oauthclient' in app.extensions

    app = Flask('testapp')
    FlaskCLI(app)
    ext = InvenioOAuthClient(app)
    assert 'invenio-oauthclient' in app.extensions

    app = Flask('testapp')
    FlaskCLI(app)
    FlaskOAuth(app)
    ext = InvenioOAuthClient()
    assert 'invenio-oauthclient' not in app.extensions
    ext.init_app(app)
    assert 'invenio-oauthclient' in app.extensions


class _CustomOAuthRemoteApp(OAuthRemoteApp):
    """Custom OAuthRemoteApp used for testing."""


def test_standard_remote_app_factory(base_app):
    """Test standard remote_app class."""
    base_app.config.update(
        OAUTHCLIENT_REMOTE_APPS=dict(
            custom_app=REMOTE_APP
        )
    )
    FlaskOAuth(base_app)
    InvenioOAuthClient(base_app)
    assert isinstance(
        base_app.extensions['oauthlib.client'].remote_apps['custom_app'],
        OAuthRemoteApp)
    assert not isinstance(
        base_app.extensions['oauthlib.client'].remote_apps['custom_app'],
        _CustomOAuthRemoteApp)


def test_remote_app_factory_global_customization(base_app):
    """Test remote_app override with global variable."""
    base_app.config.update(
        OAUTHCLIENT_REMOTE_APP=_CustomOAuthRemoteApp,
        OAUTHCLIENT_REMOTE_APPS=dict(
            custom_app=REMOTE_APP
        )
    )
    FlaskOAuth(base_app)
    InvenioOAuthClient(base_app)
    assert isinstance(
        base_app.extensions['oauthlib.client'].remote_apps['custom_app'],
        _CustomOAuthRemoteApp)


def test_remote_app_factory_local_customization(base_app):
    """Test custom remote_app for one app only."""
    config_for_one_app = deepcopy(REMOTE_APP)
    config_for_one_app['remote_app'] = _CustomOAuthRemoteApp
    base_app.config.update(
        OAUTHCLIENT_REMOTE_APPS=dict(
            custom_app=config_for_one_app
        )
    )
    FlaskOAuth(base_app)
    InvenioOAuthClient(base_app)
    assert isinstance(
        base_app.extensions['oauthlib.client'].remote_apps['custom_app'],
        _CustomOAuthRemoteApp)


def test_db(request):
    """Test database backend."""
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
        'SQLALCHEMY_DATABASE_URI', 'sqlite://'
    )
    FlaskCLI(app)
    InvenioDB(app)
    FlaskOAuth(app)
    InvenioOAuthClient(app)

    def teardown():
        with app.app_context():
            db.drop_all()

    request.addfinalizer(teardown)

    with app.app_context():
        if str(db.engine.url) != 'sqlite://' and \
           not database_exists(str(db.engine.url)):
                create_database(str(db.engine.url))
        db.create_all()
        tables = list(filter(lambda table: table.startswith('oauthclient'),
                             db.metadata.tables.keys()))
        assert len(tables) == 3
