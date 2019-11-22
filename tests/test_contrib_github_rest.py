# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2016-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Test case for github oauth remote app."""

from __future__ import absolute_import

from collections import namedtuple

import mock
import pytest
from flask import session, url_for
from flask_login import current_user
from flask_security import login_user
from helpers import check_redirect_location, \
    check_response_redirect_url_args, mock_response
from invenio_accounts.models import User
from six.moves.urllib_parse import parse_qs, urlparse

from invenio_oauthclient import current_oauthclient
from invenio_oauthclient._compat import _create_identifier
from invenio_oauthclient.contrib.github import authorized_rest
from invenio_oauthclient.errors import OAuthResponseError
from invenio_oauthclient.models import RemoteAccount, RemoteToken, UserIdentity
from invenio_oauthclient.views.client import serializer


def _get_state():
    return serializer.dumps({'app': 'github', 'sid': _create_identifier(),
                             'next': None, })


def test_login(app_rest):
    """Test github login."""
    client = app_rest.test_client()

    resp = client.get(
        url_for('invenio_oauthclient.rest_login', remote_app='github',
                next='/someurl/')
    )
    assert resp.status_code == 302

    params = parse_qs(urlparse(resp.location).query)
    assert params['response_type'], ['code']
    assert params['scope'] == ['user,user:email']
    assert params['redirect_uri']
    assert params['client_id']
    assert params['state']


class MockGh(object):
    """Mock gh."""

    def __init__(self, email):
        """Init."""
        self._email = email

    def emails(self):
        """Get emails."""
        Email = namedtuple('Email', 'verified primary email')
        yield Email(verified=True, primary=True,
                    email=self._email)

    def me(self):
        """Mock me."""
        Me = namedtuple('Me', 'id name login')
        return Me(id='githubuser', name='John', login='mynick')


def test_authorized_signup_valid_user(app_rest, example_github):
    """Test authorized callback with sign-up."""
    example_email = 'info@inveniosoftware.org'

    with app_rest.test_client() as c:
        # User login with email 'info'
        with mock.patch('github3.login') as MockLogin:
            MockLogin.return_value = MockGh(email='info@inveniosoftware.org')

            # Ensure remote apps have been loaded (due to before first
            # request)
            resp = c.get(url_for('invenio_oauthclient.rest_login',
                                 remote_app='github'))

            assert resp.status_code == 302

            mock_response(app_rest.extensions['oauthlib.client'], 'github',
                          example_github)

            # User authorized the requests and is redirect back
            resp = c.get(
                url_for('invenio_oauthclient.rest_authorized',
                        remote_app='github', code='test',
                        state=_get_state()))
            assert resp.status_code == 302
            expected_url_args = {
                "message": "Successfully authorized.",
                "code": 200,
            }
            check_response_redirect_url_args(resp, expected_url_args)

            # Assert database state (Sign-up complete)
            user = User.query.filter_by(email=example_email).one()
            remote = RemoteAccount.query.filter_by(user_id=user.id).one()
            RemoteToken.query.filter_by(id_remote_account=remote.id).one()
            assert user.active

            # Disconnect link
            resp = c.get(
                url_for(
                    'invenio_oauthclient.rest_disconnect',
                    remote_app='github'))
            assert resp.status_code == 302

            # User exists
            user = User.query.filter_by(email=example_email).one()
            assert 0 == UserIdentity.query.filter_by(
                method='orcid', id_user=user.id,
                id='githubuser'
            ).count()
            assert RemoteAccount.query.filter_by(user_id=user.id).count() == 0
            assert RemoteToken.query.count() == 0

        # User login with another email ('info2')
        with mock.patch('github3.login') as MockLogin:
            MockLogin.return_value = MockGh(email='info2@inveniosoftware.org')

            # User authorized the requests and is redirect back
            resp = c.get(
                url_for('invenio_oauthclient.rest_authorized',
                        remote_app='github', code='test',
                        state=_get_state()))
            assert resp.status_code == 302
            check_response_redirect_url_args(resp, expected_url_args)

            # check that exist only one account
            user = User.query.filter_by(email=example_email).one()
            assert user.email == example_email


def test_authorized_signup_username_already_exists(
                                                    app_rest, example_github,
                                                    user_rest):
    """Test authorized callback with sign-up."""
    example_email = 'another@email.it'

    with app_rest.test_client() as c:
        # User login with email 'info'
        with mock.patch('github3.login') as MockLogin:
            MockLogin.return_value = MockGh(email=example_email)

            # Ensure remote apps have been loaded (due to before first
            # request)
            resp = c.get(url_for('invenio_oauthclient.rest_login',
                                 remote_app='github'))

            assert resp.status_code == 302

            mock_response(app_rest.extensions['oauthlib.client'], 'github',
                          example_github)

            # User authorized the requests and is redirect back
            resp = c.get(
                url_for('invenio_oauthclient.rest_authorized',
                        remote_app='github', code='test',
                        state=_get_state()))
            assert resp.status_code == 302
            assert resp.location == (
                'http://localhost' +
                url_for('invenio_oauthclient.rest_signup', remote_app='github')
            )

            # User fills form to register
            resp = c.post(
                resp.headers['Location'],
                data={
                    'email': example_email,
                    'password': '123456',
                    'profile.username': 'pippo2',
                    'profile.full_name': 'pluto',
                }
            )
            assert resp.status_code == 200
            expected_json = {
                "message": "Successfully signed up.",
                "code": 200,
            }
            assert resp.json == expected_json

            # Assert database state (Sign-up complete)
            my_user = User.query.filter_by(email=example_email).one()
            remote = RemoteAccount.query.filter_by(user_id=my_user.id).one()
            RemoteToken.query.filter_by(id_remote_account=remote.id).one()
            assert my_user.active

            # Disconnect link
            resp = c.get(
                url_for(
                    'invenio_oauthclient.rest_disconnect',
                    remote_app='github'))
            assert resp.status_code == 302

            # User exists
            my_user = User.query.filter_by(email=example_email).one()
            assert 0 == UserIdentity.query.filter_by(
                method='orcid', id_user=my_user.id,
                id='githubuser'
            ).count()
            assert RemoteAccount.query.filter_by(
                user_id=my_user.id).count() == 0
            assert RemoteToken.query.count() == 0
            # assert User.query.count() == 2


def test_authorized_reject(app_rest):
    """Test a rejected request."""
    with app_rest.test_client() as c:
        c.get(url_for('invenio_oauthclient.rest_login', remote_app='github'))
        resp = c.get(
            url_for('invenio_oauthclient.rest_authorized',
                    remote_app='github', error='access_denied',
                    error_description='User denied access',
                    state=_get_state()))
        assert resp.status_code in (301, 302)
        expected_url_args = {
            "message": "You rejected the authentication request.",
            "code": 400,
        }
        check_response_redirect_url_args(resp, expected_url_args)


def test_authorized_already_authenticated(app_rest, models_fixture,
                                          example_github):
    """Test authorized callback with sign-up."""
    datastore = app_rest.extensions['invenio-accounts'].datastore
    login_manager = app_rest.login_manager

    existing_email = 'existing@inveniosoftware.org'
    user = datastore.find_user(email=existing_email)

    @login_manager.user_loader
    def load_user(user_id):
        return user

    @app_rest.route('/foo_login')
    def login():
        login_user(user)
        return 'Logged In'

    with mock.patch('github3.login') as MockLogin:
        MockLogin.return_value = MockGh(email='info@inveniosoftware.org')

        with app_rest.test_client() as client:

            # make a fake login (using my login function)
            client.get('/foo_login', follow_redirects=True)

            # Ensure remote apps have been loaded (due to before first
            # request)
            client.get(url_for('invenio_oauthclient.rest_login',
                               remote_app='github'))

            # Mock access token request
            mock_response(app_rest.extensions['oauthlib.client'], 'github',
                          example_github)

            # User then goes to 'Linked accounts' and clicks 'Connect'
            resp = client.get(
                url_for('invenio_oauthclient.rest_login', remote_app='github',
                        next='/someurl/')
            )
            assert resp.status_code == 302

            # User authorized the requests and is redirected back
            resp = client.get(
                url_for('invenio_oauthclient.rest_authorized',
                        remote_app='github', code='test',
                        state=_get_state()))

            # Assert database state (Sign-up complete)
            u = User.query.filter_by(email=existing_email).one()
            remote = RemoteAccount.query.filter_by(user_id=u.id).one()
            RemoteToken.query.filter_by(id_remote_account=remote.id).one()

            # Disconnect link
            resp = client.get(
                url_for(
                    'invenio_oauthclient.rest_disconnect',
                    remote_app='github'))
            assert resp.status_code == 302

            # User exists
            u = User.query.filter_by(email=existing_email).one()
            assert 0 == UserIdentity.query.filter_by(
                method='orcid', id_user=u.id,
                id='githubuser'
            ).count()
            assert RemoteAccount.query.filter_by(user_id=u.id).count() == 0
            assert RemoteToken.query.count() == 0


def test_not_authenticated(app_rest):
    """Test disconnect when user is not authenticated."""
    with app_rest.test_client() as client:
        assert not current_user.is_authenticated
        resp = client.get(
            url_for(
                'invenio_oauthclient.rest_disconnect',
                remote_app='github'))
        assert resp.status_code == 302


def test_authorized_rest_handler(app_rest):
    """Test authorized callback handler."""
    oauth = current_oauthclient.oauth
    remote = oauth.remote_apps['github']
    # General error
    example_response = {'error': 'error'}
    resp = authorized_rest(example_response, remote)
    expected_url_args = {
        "message": "Authorization with remote service failed.",
        "code": 400,
    }
    check_response_redirect_url_args(resp, expected_url_args)
    # Bad verification error
    example_response = {'error': 'bad_verification_code'}
    resp = authorized_rest(example_response, remote)
    check_redirect_location(resp, '/oauth/login/github/')

    # Incorrect client credentials
    example_response = {'error': 'incorrect_client_credentials'}
    with pytest.raises(OAuthResponseError):
        authorized_rest(example_response, remote)

        # Redirect uri mismatch
        example_response = {'error': 'redirect_uri_mismatch'}
        with pytest.raises(OAuthResponseError):
            authorized_rest(example_response, remote)
