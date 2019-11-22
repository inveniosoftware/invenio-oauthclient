# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2018 University of Chicago.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Test case for globus oauth remote app."""

from __future__ import absolute_import

import json
from collections import namedtuple

import pytest
from flask import session, url_for
from flask_login import current_user
from flask_oauthlib.client import OAuthResponse
from flask_security import login_user
from helpers import check_redirect_location, mock_remote_get, mock_response
from invenio_accounts.models import User
from mock import MagicMock
from six.moves.urllib_parse import parse_qs, urlparse

from invenio_oauthclient._compat import _create_identifier
from invenio_oauthclient.errors import OAuthResponseError
from invenio_oauthclient.models import RemoteAccount, RemoteToken, UserIdentity
from invenio_oauthclient.views.client import serializer


def _get_state():
    return serializer.dumps({'app': 'globus', 'sid': _create_identifier(),
                             'next': None, })


def test_login(app):
    """Test globus login."""
    client = app.test_client()

    resp = client.get(
        url_for('invenio_oauthclient.login', remote_app='globus',
                next='/someurl/')
    )
    assert resp.status_code == 302

    params = parse_qs(urlparse(resp.location).query)
    assert params['response_type'], ['code']
    assert params['scope'] == ['openid email profile']
    assert params['redirect_uri']
    assert params['client_id']
    assert params['state']


def test_authorized_signup_valid_user(app, example_globus):
    """Test authorized callback with sign-up."""

    with app.test_client() as c:
        # User login with email 'info'
        ioc = app.extensions['oauthlib.client']

        # Ensure remote apps have been loaded (due to before first request)
        resp = c.get(url_for('invenio_oauthclient.login',
                             remote_app='globus'))
        assert resp.status_code == 302

        example_info, example_token, example_account_id = example_globus
        mock_response(app.extensions['oauthlib.client'], 'globus',
                      example_token)
        example_info.update(example_account_id)
        oauth_resp = OAuthResponse(resp=None, content=json.dumps(example_info),
                                   content_type='application/json')
        mock_remote_get(ioc, 'globus', oauth_resp)

        # User authorized the requests and is redirect back
        resp = c.get(
            url_for('invenio_oauthclient.authorized',
                    remote_app='globus', code='test',
                    state=_get_state()))
        assert resp.status_code == 302
        assert resp.location == ('http://localhost/account/settings/' +
                                 'linkedaccounts/')

        # Assert database state (Sign-up complete)
        user = User.query.filter_by(email='carberry@inveniosoftware.org').one()
        remote = RemoteAccount.query.filter_by(user_id=user.id).one()
        RemoteToken.query.filter_by(id_remote_account=remote.id).one()
        assert user.active

        # Disconnect link
        resp = c.get(
            url_for('invenio_oauthclient.disconnect', remote_app='globus'))
        assert resp.status_code == 302

        # User exists
        user = User.query.filter_by(email='carberry@inveniosoftware.org').one()
        assert 0 == UserIdentity.query.filter_by(
            method='orcid', id_user=user.id,
            id='globususer'
        ).count()
        assert RemoteAccount.query.filter_by(user_id=user.id).count() == 0
        assert RemoteToken.query.count() == 0

        # User authorized the requests and is redirect back
        resp = c.get(
            url_for('invenio_oauthclient.authorized',
                    remote_app='globus', code='test',
                    state=_get_state()))
        assert resp.status_code == 302
        assert resp.location == (
            'http://localhost/' +
            'account/settings/linkedaccounts/'
        )

        # check that exist only one account
        user = User.query.filter_by(email='carberry@inveniosoftware.org').one()
        assert User.query.count() == 1


def test_authorized_reject(app):
    """Test a rejected request."""
    with app.test_client() as c:
        c.get(url_for('invenio_oauthclient.login', remote_app='globus'))
        resp = c.get(
            url_for('invenio_oauthclient.authorized',
                    remote_app='globus', error='access_denied',
                    error_description='User denied access',
                    state=_get_state()))
        assert resp.status_code in (301, 302)
        assert resp.location == (
            'http://localhost/'
        )
        # Check message flash
        assert session['_flashes'][0][0] == 'info'


def test_authorized_already_authenticated(app, models_fixture, example_globus):
    """Test authorized callback with sign-up."""
    datastore = app.extensions['invenio-accounts'].datastore
    login_manager = app.login_manager

    existing_email = 'existing@inveniosoftware.org'
    user = datastore.find_user(email=existing_email)

    @login_manager.user_loader
    def load_user(user_id):
        return user

    @app.route('/foo_login')
    def login():
        login_user(user)
        return 'Logged In'

    with app.test_client() as client:

        # make a fake login (using my login function)
        client.get('/foo_login', follow_redirects=True)
        # Ensure remote apps have been loaded (due to before first request)
        client.get(url_for('invenio_oauthclient.login', remote_app='globus'))

        ioc = app.extensions['oauthlib.client']
        example_info, example_token, example_account_id = example_globus
        mock_response(app.extensions['oauthlib.client'], 'globus',
                      example_token)
        example_info.update(example_account_id)
        oauth_resp = OAuthResponse(resp=None, content=json.dumps(example_info),
                                   content_type='application/json')
        mock_remote_get(ioc, 'globus', oauth_resp)

        # User then goes to 'Linked accounts' and clicks 'Connect'
        resp = client.get(
            url_for('invenio_oauthclient.login', remote_app='globus',
                    next='/someurl/')
        )
        assert resp.status_code == 302

        # User authorized the requests and is redirected back
        resp = client.get(
            url_for('invenio_oauthclient.authorized',
                    remote_app='globus', code='test',
                    state=_get_state()))

        # Assert database state (Sign-up complete)
        u = User.query.filter_by(email=existing_email).one()
        remote = RemoteAccount.query.filter_by(user_id=u.id).one()
        RemoteToken.query.filter_by(id_remote_account=remote.id).one()

        # Disconnect link
        resp = client.get(
            url_for('invenio_oauthclient.disconnect', remote_app='globus'))
        assert resp.status_code == 302

        # User exists
        u = User.query.filter_by(email=existing_email).one()
        assert 0 == UserIdentity.query.filter_by(
            method='globus', id_user=u.id,
            id='globususer'
        ).count()
        assert RemoteAccount.query.filter_by(user_id=u.id).count() == 0
        assert RemoteToken.query.count() == 0


def test_not_authenticated(app):
    """Test disconnect when user is not authenticated."""
    with app.test_client() as client:
        assert not current_user.is_authenticated
        resp = client.get(
            url_for('invenio_oauthclient.disconnect', remote_app='globus'))
        assert resp.status_code == 302


def test_bad_provider_response(app, example_globus):
    with app.test_client() as c:

        class MockResponse:
            code = 403

        # User login with email 'info'
        ioc = app.extensions['oauthlib.client']

        # Ensure remote apps have been loaded (due to before first request)
        resp = c.get(url_for('invenio_oauthclient.login',
                             remote_app='globus'))
        assert resp.status_code == 302

        _, example_token, _ = example_globus
        mock_response(app.extensions['oauthlib.client'], 'globus',
                      example_token)
        oauth_resp = OAuthResponse(resp=MockResponse(), content=None,
                                   content_type='application/json')
        mock_remote_get(ioc, 'globus', oauth_resp)

        with pytest.raises(OAuthResponseError):
            c.get(
                url_for('invenio_oauthclient.authorized',
                        remote_app='globus', code='test',
                        state=_get_state()))


def test_invalid_user_id_response(app, example_globus):
    with app.test_client() as c:

        # User login with email 'info'
        ioc = app.extensions['oauthlib.client']

        # Ensure remote apps have been loaded (due to before first request)
        resp = c.get(url_for('invenio_oauthclient.login',
                             remote_app='globus'))
        assert resp.status_code == 302

        example_info, example_token, _ = example_globus
        mock_response(app.extensions['oauthlib.client'], 'globus',
                      example_token)
        oauth_resp = OAuthResponse(resp=None, content=json.dumps(example_info),
                                   content_type='application/json')
        mock_remote_get(ioc, 'globus', oauth_resp)

        with pytest.raises(OAuthResponseError):
            c.get(
                url_for('invenio_oauthclient.authorized',
                        remote_app='globus', code='test',
                        state=_get_state()))
