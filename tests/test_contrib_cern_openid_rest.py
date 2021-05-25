# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2016-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Test case for CERN oauth remote app_rest."""

import os
from datetime import timedelta

import pytest
from flask import current_app, g, session, url_for
from flask_login import current_user
from flask_security import login_user, logout_user
from flask_security.utils import hash_password
from helpers import check_response_redirect_url_args, get_state, \
    mock_remote_get, mock_response
from six.moves.urllib_parse import parse_qs, urlparse

from invenio_oauthclient.contrib.cern_openid import \
    OAUTHCLIENT_CERN_OPENID_SESSION_KEY, account_info_rest, \
    disconnect_rest_handler, fetch_extra_data, get_dict_from_response
from invenio_oauthclient.models import RemoteAccount

from flask_oauthlib.client import OAuthResponse  # noqa isort:skip


@pytest.fixture()
def example_cern_openid_rest(request):
    """CERN openid example data."""
    file_path = os.path.join(os.path.dirname(__file__),
                             'data/cern_openid_response_content.json')
    with open(file_path) as response_file:
        json_data = response_file.read()

    from jwt import encode
    token = encode(dict(name="John Doe"), key="1234")
    return OAuthResponse(
        resp=None,
        content=json_data,
        content_type='application/json'
    ), dict(
        access_token=token,
        token_type='bearer',
        expires_in=1199,
        refresh_token='test_refresh_token'
    ), dict(
        user=dict(
            email='john.doe@cern.ch',
            profile=dict(username='jdoe', full_name='John Doe'),
        ),
        external_id='222222', external_method='cern_openid',
        active=True
    )


def test_fetch_extra_data(app_rest, example_cern_openid_rest):
    """Test extra data extraction."""
    example_response, example_token, _ = example_cern_openid_rest
    res = get_dict_from_response(example_response)

    # Check that groups were hidden as required
    extra_data = fetch_extra_data(res)

    assert 'person_id' in extra_data
    assert extra_data['person_id'] == "234567"


def test_account_info_rest(app_rest, example_cern_openid_rest):
    """Test account info extraction."""
    client = app_rest.test_client()
    ioc = app_rest.extensions['oauthlib.client']

    # Ensure remote apps have been loaded (due to before first request)
    client.get(url_for('invenio_oauthclient.rest_login',
                       remote_app='cern_openid'))

    example_response, _, example_account_info = example_cern_openid_rest

    mock_remote_get(ioc, 'cern_openid', example_response)

    assert account_info_rest(
        ioc.remote_apps['cern_openid'], None) == example_account_info


def test_account_setup(app_rest, example_cern_openid_rest, models_fixture):
    """Test account setup after login."""
    with app_rest.test_client() as c:
        ioc = app_rest.extensions['oauthlib.client']

        # Ensure remote apps have been loaded (due to before first request)
        resp = c.get(url_for('invenio_oauthclient.rest_login',
                             remote_app='cern_openid'))
        assert resp.status_code == 302

        example_response, example_token, example_account_info = \
            example_cern_openid_rest

        mock_response(app_rest.extensions['oauthlib.client'], 'cern_openid',
                      example_token)
        mock_remote_get(ioc, 'cern_openid', example_response)

        resp = c.get(url_for(
            'invenio_oauthclient.rest_authorized',
            remote_app='cern_openid', code='test',
            state=get_state('cern_openid')))
        assert resp.status_code == 302
        expected_url_args = {
            "message": "Successfully authorized.",
            "code": 200,
        }
        check_response_redirect_url_args(resp, expected_url_args)

        assert len(g.identity.provides) == 3

    datastore = app_rest.extensions['invenio-accounts'].datastore
    user = datastore.find_user(email='john.doe@cern.ch')
    user.password = hash_password("1234")
    assert user

    with app_rest.test_request_context():
        resp = disconnect_rest_handler(ioc.remote_apps['cern_openid'])
        assert resp.status_code >= 300

        # simulate login (account_info fetch)
        g.oauth_logged_in_with_remote = ioc.remote_apps['cern_openid']

        login_user(user)
        assert len(g.identity.provides) == 3

        logout_user()
        assert len(g.identity.provides) == 1
        assert "cern_resource" not in session
        assert OAUTHCLIENT_CERN_OPENID_SESSION_KEY not in session

        # Login again to test the disconnect handler
        g.oauth_logged_in_with_remote = ioc.remote_apps['cern_openid']
        login_user(user)
        assert len(g.identity.provides) == 3

        disconnect_rest_handler(ioc.remote_apps['cern_openid'])


def test_login(app_rest):
    """Test CERN login."""
    client = app_rest.test_client()

    resp = client.get(
        url_for('invenio_oauthclient.rest_login', remote_app='cern_openid',
                next='/someurl/')
    )
    assert resp.status_code == 302

    params = parse_qs(urlparse(resp.location).query)
    assert params['response_type'], ['code']
    assert params['redirect_uri']
    assert params['client_id']
    assert params['state']


def test_authorized_reject(app_rest):
    """Test a rejected request."""
    with app_rest.test_client() as c:
        c.get(url_for('invenio_oauthclient.rest_login',
                      remote_app='cern_openid'))
        resp = c.get(
            url_for('invenio_oauthclient.rest_authorized',
                    remote_app='cern_openid', error='access_denied',
                    error_description='User denied access',
                    state=get_state('cern_openid')))
        assert resp.status_code in (301, 302)
        expected_url_args = {
            "message": "You rejected the authentication request.",
            "code": 400,
        }
        check_response_redirect_url_args(resp, expected_url_args)


def test_account_info_not_allowed_account(app_rest, example_cern_openid_rest):
    """Test account info extraction."""
    client = app_rest.test_client()

    app_rest.config['OAUTHCLIENT_CERN_OPENID_ALLOWED_ROLES'] = [
        'another cern role'
    ]
    ioc = app_rest.extensions['oauthlib.client']

    # Ensure remote apps have been loaded (due to before first request)
    client.get(url_for('invenio_oauthclient.rest_login',
                       remote_app='cern_openid'))

    example_response, _, example_account_info = example_cern_openid_rest

    mock_remote_get(ioc, 'cern_openid', example_response)
    resp = account_info_rest(ioc.remote_apps['cern_openid'], None)
    assert g.oauth_logged_in_with_remote == ioc.remote_apps['cern_openid']

    assert resp.status_code == 302
    expected_url_args = {
        "message": "CERN account not allowed.",
        "code": 400,
    }
    check_response_redirect_url_args(resp, expected_url_args)


def test_identity_changed(app_rest, example_cern_openid_rest, models_fixture):
    def _init():
        ioc = app_rest.extensions['oauthlib.client']

        # setup the user account via cern_openid
        with app_rest.test_client() as c:
            # Ensure remote apps have been loaded (due to before first request)
            resp = c.get(url_for('invenio_oauthclient.rest_login',
                                 remote_app='cern_openid'))
            assert resp.status_code == 302

            example_response, example_token, example_account_info = \
                example_cern_openid_rest

            mock_response(app_rest.extensions['oauthlib.client'],
                          'cern_openid',
                          example_token)
            mock_remote_get(ioc, 'cern_openid', example_response)

            resp = c.get(url_for(
                'invenio_oauthclient.rest_authorized',
                remote_app='cern_openid', code='test',
                state=get_state('cern_openid')))
            assert resp.status_code == 302
            expected_url_args = {
                "message": "Successfully authorized.",
                "code": 200,
            }
            check_response_redirect_url_args(resp, expected_url_args)

            assert len(g.identity.provides) == 3

    def _test_with_token(user, remote_account):
        with app_rest.test_request_context():
            # mark user as logged in via token
            user.login_via_oauth2 = True
            # check if the initial roles are there
            login_user(user)

            assert current_user.login_via_oauth2

            assert len(g.identity.provides) == 3
            logout_user()

            # remove the cern roles
            remote_account.extra_data.update(roles=[])

            # login the user again
            login_user(user)

            # check if the cern roles are not fetched from the provider
            assert len(g.identity.provides) == 2
            logout_user()

    def _test_without_token(user, remote_account):
        user.login_via_oauth2 = False

        current_app.config[
            'OAUTHCLIENT_CERN_OPENID_REFRESH_TIMEDELTA'] = False
        login_user(user)

        # check that the roles are not refreshed from provider
        assert len(g.identity.provides) == 2
        logout_user()

        current_app.config['OAUTHCLIENT_CERN_OPENID_REFRESH_TIMEDELTA'] \
            = timedelta(microseconds=1)
        login_user(user)

        # check if roles refreshed from the provider
        assert len(g.identity.provides) == 3

    _init()

    datastore = app_rest.extensions['invenio-accounts'].datastore
    user = datastore.find_user(email='john.doe@cern.ch')
    assert user

    client_id = current_app.config["CERN_APP_OPENID_CREDENTIALS"][
        "consumer_key"
    ]
    # make sure the roles are cleaned
    remote_account = RemoteAccount.get(
        user_id=user.get_id(), client_id=client_id
    )

    _test_with_token(user, remote_account)
    _test_without_token(user, remote_account)
