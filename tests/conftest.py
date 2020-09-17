# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2018 CERN.
# Copyright (C) 2018 University of Chicago.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Pytest configuration."""

from __future__ import absolute_import, print_function

import json
import os
import shutil
import tempfile

import pytest
from flask import Flask
from flask_babelex import Babel
from flask_mail import Mail
from flask_menu import Menu as FlaskMenu
from invenio_accounts import InvenioAccounts
from invenio_db import InvenioDB, db
from invenio_userprofiles import InvenioUserProfiles, UserProfile
from invenio_userprofiles.views import blueprint_ui_init
from sqlalchemy_utils.functions import create_database, database_exists, \
    drop_database

from invenio_oauthclient import InvenioOAuthClient, InvenioOAuthClientREST
from invenio_oauthclient.contrib.cern import REMOTE_APP as CERN_REMOTE_APP
from invenio_oauthclient.contrib.cern import \
    REMOTE_REST_APP as CERN_REMOTE_REST_APP
from invenio_oauthclient.contrib.cern_openid import \
    REMOTE_APP as CERN_OPENID_REMOTE_APP
from invenio_oauthclient.contrib.cern_openid import \
    REMOTE_REST_APP as CERN_OPENID_REMOTE_REST_APP
from invenio_oauthclient.contrib.github import REMOTE_APP as GITHUB_REMOTE_APP
from invenio_oauthclient.contrib.github import \
    REMOTE_REST_APP as GITHUB_REMOTE_REST_APP
from invenio_oauthclient.contrib.globus import REMOTE_APP as GLOBUS_REMOTE_APP
from invenio_oauthclient.contrib.globus import \
    REMOTE_REST_APP as GLOBUS_REMOTE_REST_APP
from invenio_oauthclient.contrib.orcid import REMOTE_APP as ORCID_REMOTE_APP
from invenio_oauthclient.contrib.orcid import \
    REMOTE_REST_APP as ORCID_REMOTE_REST_APP
from invenio_oauthclient.views.client import blueprint as blueprint_client
from invenio_oauthclient.views.client import rest_blueprint
from invenio_oauthclient.views.settings import blueprint as blueprint_settings

from invenio_oauthclient._compat import monkey_patch_werkzeug  # noqa isort:skip

try:
    from werkzeug.middleware.dispatcher import DispatcherMiddleware
except ImportError:
    from werkzeug.wsgi import DispatcherMiddleware

from flask_oauthlib.client import OAuth as FlaskOAuth  # noqa isort:skip
from flask_oauthlib.client import OAuthResponse  # noqa isort:skip


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
            cern_openid=CERN_OPENID_REMOTE_APP,
            orcid=ORCID_REMOTE_APP,
            github=GITHUB_REMOTE_APP,
            globus=GLOBUS_REMOTE_APP,
        ),
        OAUTHCLIENT_REST_REMOTE_APPS=dict(
            cern=CERN_REMOTE_REST_APP,
            cern_openid=CERN_OPENID_REMOTE_REST_APP,
            orcid=ORCID_REMOTE_REST_APP,
            github=GITHUB_REMOTE_REST_APP,
            globus=GLOBUS_REMOTE_REST_APP,
        ),
        OAUTHCLIENT_STATE_EXPIRES=300,
        GITHUB_APP_CREDENTIALS=dict(
            consumer_key='github_key_changeme',
            consumer_secret='github_secret_changeme',
        ),
        ORCID_APP_CREDENTIALS=dict(
            consumer_key='orcid_key_changeme',
            consumer_secret='orcid_secret_changeme',
        ),
        CERN_APP_CREDENTIALS=dict(
            consumer_key='cern_key_changeme',
            consumer_secret='cern_secret_changeme',
        ),
        CERN_APP_OPENID_CREDENTIALS=dict(
            consumer_key='cern_key_changeme',
            consumer_secret='cern_secret_changeme',
        ),
        GLOBUS_APP_CREDENTIALS=dict(
            consumer_key='globus_key_changeme',
            consumer_secret='globus_secret_changeme',
        ),
        # use local memory mailbox
        EMAIL_BACKEND='flask_email.backends.locmem.Mail',
        SQLALCHEMY_DATABASE_URI=os.getenv('SQLALCHEMY_DATABASE_URI',
                                          'sqlite://'),
        SERVER_NAME='localhost',
        DEBUG=False,
        SECRET_KEY='TEST',
        SECURITY_DEPRECATED_PASSWORD_SCHEMES=[],
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SECURITY_PASSWORD_HASH='plaintext',
        SECURITY_PASSWORD_SCHEMES=['plaintext'],
        APP_ALLOWED_HOSTS=['localhost']
    )
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


def _init_app(app_):
    """Init OAuth app."""
    app_.config.update(
        WTF_CSRF_ENABLED=False,
    )
    FlaskOAuth(app_)
    InvenioOAuthClient(app_)
    app_.register_blueprint(blueprint_client)
    app_.register_blueprint(blueprint_settings)
    return app_


def _init_app_rest(app_):
    """Init OAuth rest app."""
    FlaskOAuth(app_)
    InvenioOAuthClientREST(app_)
    app_.register_blueprint(rest_blueprint)
    return app_


@pytest.fixture
def app(base_app):
    """Flask application fixture."""
    return _init_app(base_app)


@pytest.fixture
def app_rest(base_app, views_fixture_rest):
    """Flask application fixture."""
    return _init_app_rest(base_app)


@pytest.fixture
def app_with_csrf(base_app):
    """Flask application fixture with CSRF enabled."""
    app_ = _init_app(base_app)
    app_.config.update(
        WTF_CSRF_ENABLED=True,
    )
    return app_


@pytest.fixture
def app_rest_with_userprofiles(app_rest):
    """Configure userprofiles module with CSRF disabled."""
    app_rest.config.update(
        USERPROFILES_EXTEND_SECURITY_FORMS=True,
        WTF_CSRF_ENABLED=False,
    )
    return _init_userprofiles(app_rest)


def _init_userprofiles(app_):
    """Init userprofiles module."""
    InvenioUserProfiles(app_)
    app_.register_blueprint(blueprint_ui_init)
    return app_


@pytest.fixture
def app_with_userprofiles(app):
    """Configure userprofiles module with CSRF disabled."""
    app.config.update(
        USERPROFILES_EXTEND_SECURITY_FORMS=True,
        WTF_CSRF_ENABLED=False,
    )
    return _init_userprofiles(app)


@pytest.fixture
def app_with_userprofiles_csrf(app):
    """Configure userprofiles module with CSRF enabled."""
    app.config.update(
        USERPROFILES_EXTEND_SECURITY_FORMS=True,
        WTF_CSRF_ENABLED=True,
    )
    return _init_userprofiles(app)


@pytest.fixture
def models_fixture(base_app):
    """Flask app with example data used to test models."""
    with base_app.app_context():
        datastore = base_app.extensions['security'].datastore
        datastore.create_user(
            email='existing@inveniosoftware.org',
            password='tester',
            active=True
        )
        datastore.create_user(
            email='test2@inveniosoftware.org',
            password='tester',
            active=True
        )
        datastore.create_user(
            email='test3@inveniosoftware.org',
            password='tester',
            active=True
        )
        datastore.commit()


@pytest.fixture
def params():
    """Fixture for remote app params."""
    def params(x):
        return dict(
            request_token_params={'scope': ''},
            base_url='https://foo.bar/',
            request_token_url=None,
            access_token_url='https://foo.bar/oauth/access_token',
            authorize_url='https://foo.bar/oauth/authorize',
            consumer_key=x,
            consumer_secret='testsecret',
        )

    return params


@pytest.fixture
def remote():
    """Fixture for remote app."""
    return type('test_remote', (), dict(
        name='example_remote',
        request_token_params={'scope': ''},
        base_url='https://foo.bar/',
        request_token_url=None,
        access_token_url='https://foo.bar/oauth/access_token',
        authorize_url='https://foo.bar/oauth/authorize',
        consumer_key='testkey',
        consumer_secret='testsecret',
    ))()


@pytest.fixture
def views_fixture(base_app, params, models_fixture):
    """Flask application with example data used to test views."""
    base_app.config['OAUTHCLIENT_REMOTE_APPS'].update(
        dict(
            test=dict(
                authorized_handler=lambda *args, **kwargs: 'TEST',
                params=params('testid'),
                title='MyLinkedTestAccount',
            ),
            test_invalid=dict(
                authorized_handler=lambda *args, **kwargs: 'TEST',
                params=params('test_invalidid'),
                title='Test Invalid',
            ),
            full=dict(
                params=params('fullid'),
                title='Full',
            ),
        )
    )

    return _init_app(base_app)


@pytest.fixture
def views_fixture_rest(base_app, params, models_fixture):
    """Flask application with example data used to test views."""
    base_app.config['OAUTHCLIENT_REST_REMOTE_APPS'].update(
        dict(
            test=dict(
                authorized_handler=lambda *args, **kwargs: 'TEST',
                authorized_redirect_url='/',
                disconnect_redirect_url='/',
                signup_redirect_url='/',
                error_redirect_url='/',
                params=params('testid'),
                title='MyLinkedTestAccount',
            ),
            test_invalid=dict(
                authorized_handler=lambda *args, **kwargs: 'TEST',
                authorized_redirect_url='/',
                disconnect_redirect_url='/',
                signup_redirect_url='/',
                error_redirect_url='/',
                params=params('test_invalidid'),
                title='Test Invalid',
            ),
            full=dict(
                params=params('fullid'),
                authorized_redirect_url='/',
                disconnect_redirect_url='/',
                signup_redirect_url='/',
                error_redirect_url='/',
                title='Full',
            ),
        )
    )


@pytest.fixture
def example_github(request):
    """ORCID example data."""
    return {
        'name': 'Josiah Carberry',
        'expires_in': 3599,
        'access_token': 'test_access_token',
        'refresh_token': 'test_refresh_token',
        'scope': '/authenticate',
        'token_type': 'bearer',
    }


@pytest.fixture
def example_globus(request):
    """Globus example data."""
    return {
                'identity_provider_display_name': 'Globus ID',
                'sub': '1142af3a-fea4-4df9-afe2-865ccd68bfdb',
                'preferred_username': 'carberry@inveniosoftware.org',
                'identity_provider': '41143743-f3c8-4d60-bbdb-eeecaba85bd9',
                'organization': 'Globus',
                'email': 'carberry@inveniosoftware.org',
                'name': 'Josiah Carberry'
            }, {
                'expires_in': 3599,
                'resource_server': 'auth.globus.org',
                'state': 'test_state',
                'access_token': 'test_access_token',
                'id_token': 'header.test-oidc-token.pub-key',
                'other_tokens': [],
                'scope': 'profile openid email',
                'token_type': 'Bearer',
            }, {
                'identities': [
                    {
                        'username': 'carberry@inveniosoftware.org',
                        'status': 'used',
                        'name': 'Josiah Carberry',
                        'email': 'carberry@inveniosoftware.org',
                        'identity_provider':
                            '927d7238-f917-4eb2-9ace-c523fa9ba34e',
                        'organization': 'Globus',
                        'id': '3b843349-4d4d-4ef3-916d-2a465f9740a9'
                    }
                ]
    }


@pytest.fixture
def example_orcid(request):
    """ORCID example data."""
    return {
               'name': 'Josiah Carberry',
               'expires_in': 3599,
               'orcid': '0000-0002-1825-0097',
               'access_token': 'test_access_token',
               'refresh_token': 'test_refresh_token',
               'scope': '/authenticate',
               'token_type': 'bearer'
           }, dict(external_id='0000-0002-1825-0097',
                   external_method='orcid',
                   user=dict(
                       profile=dict(
                           full_name='Josiah Carberry'
                       )
                   )
                   )


@pytest.fixture()
def example_cern(request):
    """CERN example data."""
    file_path = os.path.join(os.path.dirname(__file__),
                             'data/oauth_response_content.json')
    with open(file_path) as response_file:
        json_data = response_file.read()

    return OAuthResponse(
        resp=None,
        content=json_data,
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
def user(app_with_userprofiles):
    """Create users."""
    with db.session.begin_nested():
        datastore = app_with_userprofiles.extensions['security'].datastore
        user1 = datastore.create_user(email='info@inveniosoftware.org',
                                      password='tester', active=True)
        profile = UserProfile(username='mynick', user=user1)
        db.session.add(profile)
    db.session.commit()
    return user1


@pytest.fixture()
def user_rest(app_rest_with_userprofiles):
    """Create users."""
    with db.session.begin_nested():
        datastore = app_rest_with_userprofiles.extensions['security'].datastore
        user1 = datastore.create_user(email='info@inveniosoftware.org',
                                      password='tester', active=True)
        profile = UserProfile(username='mynick', user=user1)
        db.session.add(profile)
    db.session.commit()
    return user1


@pytest.fixture()
def form_test_data():
    """Test data to fill a registration form."""
    return dict(
                email='test@tester.com',
                profile=dict(
                    full_name='Test Tester',
                    username='test123',
                ),
            )
