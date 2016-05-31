# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015, 2016 CERN.
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

"""Pytest configuration."""

from __future__ import absolute_import, print_function

import os
import json
import shutil
import tempfile

import pytest
from flask import Flask
from flask_babelex import Babel
from flask_cli import FlaskCLI
from flask_mail import Mail
from flask_menu import Menu as FlaskMenu
from flask_oauthlib.client import OAuth as FlaskOAuth
from invenio_accounts import InvenioAccounts
from invenio_db import InvenioDB, db
from sqlalchemy_utils.functions import create_database, database_exists, \
    drop_database

from invenio_oauthclient import InvenioOAuthClient
from invenio_oauthclient.contrib.orcid import REMOTE_APP
from invenio_oauthclient.views.client import blueprint as blueprint_client
from invenio_oauthclient.views.settings import blueprint as blueprint_settings


@pytest.fixture
def base_app(request):
    """Flask application fixture without OAuthClient initialized."""
    instance_path = tempfile.mkdtemp()
    base_app = Flask('testapp')
    base_app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        LOGIN_DISABLED=False,
        CACHE_TYPE='simple',
        OAUTHCLIENT_REMOTE_APPS=dict(
            orcid=REMOTE_APP,
        ),
        ORCID_APP_CREDENTIALS=dict(
            consumer_key='changeme',
            consumer_secret='changeme',
        ),
        # use local memory mailbox
        EMAIL_BACKEND='flask_email.backends.locmem.Mail',
        SQLALCHEMY_DATABASE_URI=os.getenv('SQLALCHEMY_DATABASE_URI',
                                          'sqlite://'),
        SERVER_NAME='localhost',
        DEBUG=False,
        SECRET_KEY='TEST',
        SECURITY_DEPRECATED_PASSWORD_SCHEMES=[],
        SECURITY_PASSWORD_HASH='plaintext',
        SECURITY_PASSWORD_SCHEMES=['plaintext'],
    )
    FlaskCLI(base_app)
    FlaskMenu(base_app)
    Babel(base_app)
    Mail(base_app)
    InvenioDB(base_app)
    InvenioAccounts(base_app)

    with base_app.app_context():
        if str(db.engine.url) != 'sqlite://' and \
           not database_exists(str(db.engine.url)):
                create_database(str(db.engine.url))
        db.create_all()

    def teardown():
        with base_app.app_context():
            db.session.close()
            if str(db.engine.url) != 'sqlite://':
                drop_database(str(db.engine.url))
            shutil.rmtree(instance_path)

    request.addfinalizer(teardown)

    base_app.test_request_context().push()

    return base_app


@pytest.fixture
def app(base_app):
    """Flask application fixture."""
    FlaskOAuth(base_app)
    InvenioOAuthClient(base_app)
    base_app.register_blueprint(blueprint_client)
    base_app.register_blueprint(blueprint_settings)
    return base_app


@pytest.fixture
def models_fixture(app):
    """Flask app with example data used to test models."""
    with app.app_context():
        datastore = app.extensions['security'].datastore
        datastore.create_user(
            email="existing@invenio-software.org",
            password='tester',
            active=True
        )
        datastore.create_user(
            email="test2@invenio-software.org",
            password='tester',
            active=True
        )
        datastore.create_user(
            email="test3@invenio-software.org",
            password='tester',
            active=True
        )
        datastore.commit()
    return app


@pytest.fixture
def params():
    """Fixture for remote app params."""
    def params(x):
        return dict(
            request_token_params={'scope': ''},
            base_url='https://foo.bar/',
            request_token_url=None,
            access_token_url="https://foo.bar/oauth/access_token",
            authorize_url="https://foo.bar/oauth/authorize",
            consumer_key=x,
            consumer_secret='testsecret',
        )

    return params


@pytest.fixture
def views_fixture(base_app, params):
    """Flask application with example data used to test views."""
    with base_app.app_context():
        datastore = base_app.extensions['security'].datastore
        datastore.create_user(
            email="existing@invenio-software.org",
            password='tester',
            active=True
        )
        datastore.create_user(
            email="test2@invenio-software.org",
            password='tester',
            active=True
        )
        datastore.create_user(
            email="test3@invenio-software.org",
            password='tester',
            active=True
        )
        datastore.commit()

    base_app.config['OAUTHCLIENT_REMOTE_APPS'].update(
        dict(
            test=dict(
                authorized_handler=lambda *args, **kwargs: "TEST",
                params=params('testid'),
                title='MyLinkedTestAccount',
            ),
            test_invalid=dict(
                authorized_handler=lambda *args, **kwargs: "TEST",
                params=params('test_invalidid'),
                title='Test Invalid',
            ),
            full=dict(
                params=params("fullid"),
                title='Full',
            ),
        )
    )

    FlaskOAuth(base_app)
    InvenioOAuthClient(base_app)
    base_app.register_blueprint(blueprint_client)
    base_app.register_blueprint(blueprint_settings)

    return base_app


@pytest.fixture
def example(request):
    """Example data."""
    return {
        "name": "Josiah Carberry",
        "expires_in": 3599,
        "orcid": "0000-0002-1825-0097",
        "access_token": "test_access_token",
        "refresh_token": "test_refresh_token",
        "scope": "/authenticate",
        "token_type": "bearer"
    }, dict(external_id="0000-0002-1825-0097",
            external_method="orcid",
            nickname="0000-0002-1825-0097")


@pytest.fixture(scope='session')
def orcid_bio():
    """ORCID response fixture."""
    file_path = os.path.join(os.path.dirname(__file__), 'data/orcid_bio.json')
    with open(file_path) as response_file:
        data = json.load(response_file)
    return data
