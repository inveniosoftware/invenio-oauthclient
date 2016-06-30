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

import json
import os
import shutil
import tempfile

import pytest
from flask import Flask
from flask_babelex import Babel
from flask_cli import FlaskCLI
from flask_mail import Mail
from flask_menu import Menu as FlaskMenu
from flask_oauthlib.client import OAuth as FlaskOAuth
from flask_oauthlib.client import OAuthResponse
from invenio_accounts import InvenioAccounts
from invenio_db import InvenioDB, db
from invenio_userprofiles import InvenioUserProfiles, UserProfile
from invenio_userprofiles.views import blueprint_ui_init
from sqlalchemy_utils.functions import create_database, database_exists, \
    drop_database

from invenio_oauthclient import InvenioOAuthClient
from invenio_oauthclient.contrib.cern import REMOTE_APP as CERN_REMOTE_APP
from invenio_oauthclient.contrib.github import REMOTE_APP as GITHUB_REMOTE_APP
from invenio_oauthclient.contrib.orcid import REMOTE_APP as ORCID_REMOTE_APP
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
            cern=CERN_REMOTE_APP,
            orcid=ORCID_REMOTE_APP,
            github=GITHUB_REMOTE_APP,
        ),
        GITHUB_APP_CREDENTIALS=dict(
            consumer_key='changeme',
            consumer_secret='changeme',
        ),
        ORCID_APP_CREDENTIALS=dict(
            consumer_key='changeme',
            consumer_secret='changeme',
        ),
        CERN_APP_CREDENTIALS=dict(
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
def userprofiles_app(app):
    """Configure userprofiles module."""
    app.config.update(
        USERPROFILES_EXTEND_SECURITY_FORMS=True,
    )
    InvenioUserProfiles(app)
    app.register_blueprint(blueprint_ui_init)
    return app


@pytest.fixture
def models_fixture(app):
    """Flask app with example data used to test models."""
    with app.app_context():
        datastore = app.extensions['security'].datastore
        datastore.create_user(
            email="existing@inveniosoftware.org",
            password='tester',
            active=True
        )
        datastore.create_user(
            email="test2@inveniosoftware.org",
            password='tester',
            active=True
        )
        datastore.create_user(
            email="test3@inveniosoftware.org",
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
            email="existing@inveniosoftware.org",
            password='tester',
            active=True
        )
        datastore.create_user(
            email="test2@inveniosoftware.org",
            password='tester',
            active=True
        )
        datastore.create_user(
            email="test3@inveniosoftware.org",
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
def example_github(request):
    """ORCID example data."""
    return {
        "name": "Josiah Carberry",
        "expires_in": 3599,
        "access_token": "test_access_token",
        "refresh_token": "test_refresh_token",
        "scope": "/authenticate",
        "token_type": "bearer",
    }


@pytest.fixture
def example_orcid(request):
    """ORCID example data."""
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
            user=dict())


@pytest.fixture()
def example_cern(request):
    """CERN example data."""
    return OAuthResponse(
        resp=None,
        content='''[
            {"Type": "http://schemas.xmlsoap.org/claims/PersonID", "Value": "123456"},
            {"Type": "http://schemas.xmlsoap.org/claims/EmailAddress", "Value": "test.account@cern.ch"},
            {"Type": "http://schemas.xmlsoap.org/claims/CommonName", "Value": "taccount"},
            {"Type": "http://schemas.xmlsoap.org/claims/DisplayName", "Value": "Test Account"},
            {"Type": "http://schemas.xmlsoap.org/claims/Group", "Value": "Group1"},
            {"Type": "http://schemas.xmlsoap.org/claims/Group", "Value": "Group2"},
            {"Type": "http://schemas.xmlsoap.org/claims/Group", "Value": "Group3"},
            {"Type": "http://schemas.xmlsoap.org/claims/Group", "Value": "Group4"},
            {"Type": "http://schemas.xmlsoap.org/claims/Group", "Value": "Group5"},
            {"Type": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", "Value": "test.account@cern.ch"},
            {"Type": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn", "Value": "test.account@cern.ch"},
            {"Type": "http://schemas.xmlsoap.org/claims/UPN", "Value": "test.account@cern.ch"},
            {"Type": "http://schemas.microsoft.com/ws/2008/06/identity/claims/role", "Value": "CERN Users"},
            {"Type": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", "Value": "Test Account"},
            {"Type": "http://schemas.xmlsoap.org/claims/PhoneNumber", "Value": "+41123456789"},
            {"Type": "http://schemas.xmlsoap.org/claims/Building", "Value": "000 1-222"},
            {"Type": "http://schemas.xmlsoap.org/claims/Firstname", "Value": "Test"},
            {"Type": "http://schemas.xmlsoap.org/claims/Lastname", "Value": "Account"},
            {"Type": "http://schemas.xmlsoap.org/claims/Department", "Value": "IT/CDA"},
            {"Type": "http://schemas.xmlsoap.org/claims/HomeInstitute", "Value": "CERN"},
            {"Type": "http://schemas.xmlsoap.org/claims/uidNumber", "Value": "54321"},
            {"Type": "http://schemas.xmlsoap.org/claims/gidNumber", "Value": "1122"},
            {"Type": "http://schemas.xmlsoap.org/claims/PreferredLanguage", "Value": "EN"},
            {"Type": "http://schemas.xmlsoap.org/claims/IdentityClass", "Value": "CERN Registered"},
            {"Type": "http://schemas.xmlsoap.org/claims/Federation", "Value": "CERN"},
            {"Type": "http://schemas.xmlsoap.org/claims/AuthLevel", "Value": "Normal"},
            {"Type": "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod", "Value": "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password"},
            {"Type": "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationinstant", "Value": "2016-01-20T21:44:08.554Z"},
            {"Type": "urn:oauth:scope", "Value": "Name"},
            {"Type": "urn:oauth:scope", "Value": "Email"},
            {"Type": "urn:oauth:scope", "Value": "Bio"},
            {"Type": "urn:oauth:scope", "Value": "Groups"}
            ]''',
        content_type='application/json'
    ), dict(
        access_token='test_access_token',
        token_type='bearer',
        expires_in=1199,
        refresh_token='test_refresh_token'
    ), dict(
        user=dict(
            email='test.account@cern.ch',
            profile=dict(username='taccount', full_name='Test Account'),
        ),
        external_id='123456', external_method='cern',
        active=True
    )


@pytest.fixture(scope='session')
def orcid_bio():
    """ORCID response fixture."""
    file_path = os.path.join(os.path.dirname(__file__), 'data/orcid_bio.json')
    with open(file_path) as response_file:
        data = json.load(response_file)
    return data


@pytest.fixture()
def user(userprofiles_app):
    """Create users."""
    with db.session.begin_nested():
        datastore = userprofiles_app.extensions['security'].datastore
        user1 = datastore.create_user(email='info@inveniosoftware.org',
                                      password='tester', active=True)
        profile = UserProfile(username='mynick', user=user1)
        db.session.add(profile)
    db.session.commit()
    return user1
