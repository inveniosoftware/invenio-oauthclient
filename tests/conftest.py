# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015 CERN.
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

import pytest

from invenio_accounts import InvenioAccounts

from invenio_oauthclient import InvenioOAuthClient
from invenio_oauthclient.contrib.orcid import REMOTE_APP
from invenio_oauthclient.views.client import blueprint as blueprint_client
from invenio_oauthclient.views.settings import blueprint as blueprint_settings

from invenio_db import InvenioDB, db

from flask import Flask

from flask_babelex import Babel

from flask_cli import FlaskCLI

from flask_mail import Mail

from flask_menu import Menu as FlaskMenu

from flask_oauthlib.client import OAuth as FlaskOAuth


@pytest.fixture()
def app(request):
    """Flask application fixture."""
    config = dict(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        OAUTHCLIENT_STATE_ENABLED=False,
        CACHE_TYPE='simple',
        OAUTHCLIENT_REMOTE_APPS=dict(orcid=REMOTE_APP),
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
    )

    app = gen_app(config)

    def teardown():
        with app.app_context():
            db.drop_all()

    request.addfinalizer(teardown)

    return app


def gen_app(config):
    """Generate a fresh app."""
    app = Flask('testapp')
    app.testing = True
    app.config.update(**config)

    FlaskCLI(app)
    FlaskMenu(app)
    Babel(app)
    Mail(app)
    InvenioDB(app)
    InvenioAccounts(app)
    FlaskOAuth(app)
    InvenioOAuthClient(app)

    app.register_blueprint(blueprint_client)
    app.register_blueprint(blueprint_settings)

    with app.app_context():
        db.create_all()

    app.test_request_context().push()

    datastore = app.extensions['invenio-accounts'].datastore

    datastore.create_user(
        email="existing@invenio-software.org", password='tester', active=True)
    datastore.create_user(
        email="test2@invenio-software.org", password='tester', active=True)
    datastore.create_user(
        email="test3@invenio-software.org", password='tester', active=True)
    datastore.commit()

    return app


@pytest.fixture()
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
