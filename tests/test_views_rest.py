# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Test case for views."""

import time

import pytest
from flask import url_for
from flask_oauthlib.client import OAuth as FlaskOAuth
from helpers import check_response_redirect_url, \
    check_response_redirect_url_args
from invenio_accounts.testutils import login_user_via_session
from invenio_db import db
from itsdangerous import TimedJSONWebSignatureSerializer
from mock import MagicMock
from simplejson import JSONDecodeError
from six.moves.urllib_parse import parse_qs, urlparse

from invenio_oauthclient import InvenioOAuthClientREST
from invenio_oauthclient._compat import _create_identifier
from invenio_oauthclient.handlers import token_getter
from invenio_oauthclient.models import RemoteToken
from invenio_oauthclient.views.client import rest_blueprint, serializer


def mock_response(oauth, remote_app='test', data=None):
    """Mock the oauth response to use the remote."""
    # Mock oauth remote application
    oauth.remote_apps[remote_app].handle_oauth2_response = MagicMock(
        return_value=data or {
            'access_token': 'test_access_token',
            'scope': "",
            'token_type': 'bearer'
        }
    )


def test_redirect_uri(app_rest):
    """Test redirect uri."""
    with app_rest.test_client() as client:
        # Test redirect
        resp = client.get(
            url_for(
                'invenio_oauthclient.rest_login',
                remote_app='test',
                next='http://inveniosoftware.org'))
        assert resp.status_code == 302

        # Verify parameters
        params = parse_qs(urlparse(resp.location).query)
        assert params['response_type'] == ['code']
        assert params['client_id'] == ['testid']
        assert params['redirect_uri']
        assert params['state']

        # Verify next parameter in state token does not allow blanco redirects
        state = serializer.loads(params['state'][0])
        assert state['next'] is None

        # Assert redirect uri does not have any parameters.
        params = parse_qs(urlparse(params['redirect_uri'][0]).query)
        assert params == {}

        # Assert that local redirects are allowed
        test_urls = [
            '/',
            '/search'
        ]
        for url in test_urls:
            resp = client.get(
                url_for(
                    'invenio_oauthclient.rest_login',
                    remote_app='test', next=url))
            check_response_redirect_url(resp, url)

        # Assert that absolute redirects are allowed only if
        # `APP_ALLOWED_HOSTS` is set and includes them. Otherwise, the relative
        # path of the url is extracted and returned. Note if you need to
        # redirect to index page you should pass '/' as next parameter.

        test_url = 'http://inveniosoftware.org/test'

        resp = client.get(
            url_for(
                'invenio_oauthclient.rest_login',
                remote_app='test', next=test_url))

        check_response_redirect_url(resp, urlparse(test_url).path)

        app_rest.config.update({"APP_ALLOWED_HOSTS": ["inveniosoftware.org"]})

        resp = client.get(
            url_for(
                'invenio_oauthclient.rest_login',
                remote_app='test', next=test_url))

        check_response_redirect_url(resp, test_url)


def test_login(app_rest):
    """Test login."""
    with app_rest.test_client() as client:
        # Test redirect
        resp = client.get(
            url_for(
                'invenio_oauthclient.rest_login',
                remote_app='test', next='/'))
        assert resp.status_code == 302

        params = parse_qs(urlparse(resp.location).query)
        assert params['response_type'] == ['code']
        assert params['client_id'] == ['testid']
        assert params['redirect_uri']
        assert params['state']

        # Invalid remote
        resp = client.get(
            url_for('invenio_oauthclient.rest_login', remote_app='invalid'),
            follow_redirects=True
        )
        assert resp.status_code == 404


def test_authorized(base_app, params):
    """Test login."""
    handled = {}

    def test_authorized_handler(resp, remote, *args, **kwargs):
        """Save configuration."""
        handled['resp'] = resp
        handled['remote'] = remote
        handled['args'] = args
        handled['kwargs'] = kwargs
        return 'TEST'

    def test_invalid_authorized_handler(resp, remote, *args, **kwargs):
        """Set wrong configuration."""
        handled['resp'] = 1
        handled['remote'] = 1
        handled['args'] = 1
        handled['kwargs'] = 1

    base_app.config['OAUTHCLIENT_REST_REMOTE_APPS'].update(
        dict(
            test=dict(
                authorized_handler=test_authorized_handler,
                params=params('testid'),
                title='MyLinkedTestAccount',
            ),
            test_invalid=dict(
                authorized_handler=test_invalid_authorized_handler,
                params=params('test_invalidid'),
                title='Test Invalid',
            ),
            full=dict(
                params=params('fullid'),
                title='Full',
            ),
        ))

    FlaskOAuth(base_app)
    InvenioOAuthClientREST(base_app)
    base_app.register_blueprint(rest_blueprint)

    with base_app.test_client() as client:
        # Ensure remote apps have been loaded (due to before first
        # request)
        client.get(url_for(
            'invenio_oauthclient.rest_login', remote_app='test'))
        mock_response(base_app.extensions['oauthlib.client'], 'test')
        mock_response(base_app.extensions['oauthlib.client'], 'test_invalid')

        from invenio_oauthclient.views.client import serializer

        state = serializer.dumps({
            'app': 'test',
            'sid': _create_identifier(),
            'next': None,
        })

        resp = client.get(
            url_for(
                'invenio_oauthclient.rest_authorized',
                remote_app='test',
                code='test',
                state=state
            )
        )
        assert resp.data == b'TEST'
        assert handled['remote'].name == 'test'
        assert not handled['args']
        assert not handled['kwargs']
        assert handled['resp']['access_token'] == 'test_access_token'

        state = serializer.dumps({
            'app': 'test_invalid',
            'sid': _create_identifier(),
            'next': None,
        })

        # handler should return something
        # Flask>1.0 is throwing TypeError and Flask<1.0 ValueError
        with pytest.raises((ValueError, TypeError)):
            client.get(url_for(
                'invenio_oauthclient.rest_authorized',
                remote_app='test_invalid',
                code='test',
                state=state,
            ))


def test_invalid_authorized_response(app_rest):
    """Test login."""
    oauth = app_rest.extensions['oauthlib.client']
    with app_rest.test_client() as client:
        # Fake an authorized request
        # Ensure remote apps have been loaded (due to before first
        # request)
        client.get(url_for(
            'invenio_oauthclient.rest_login', remote_app='test'))

        oauth.remote_apps['test'].handle_oauth2_response = MagicMock(
            side_effect=JSONDecodeError('Expecting value', '', 0)
        )

        state = serializer.dumps({
            'app': 'test',
            'sid': _create_identifier(),
            'next': None,
        })

        with pytest.raises(JSONDecodeError):
            client.get(url_for(
                'invenio_oauthclient.rest_authorized',
                remote_app='test',
                code='test',
                state=state
            ))


def test_state_token(app_rest, monkeypatch):
    """Test state token."""
    # Mock session id
    monkeypatch.setattr('invenio_oauthclient._compat._create_identifier',
                        lambda: '1234')
    monkeypatch.setattr(
        'invenio_oauthclient.views.client._create_identifier', lambda: '1234')

    with app_rest.test_client() as client:
        # Ensure remote apps have been loaded (due to before first
        # request)
        client.get(url_for(
            'invenio_oauthclient.rest_login', remote_app='test'))
        mock_response(app_rest.extensions['oauthlib.client'], 'test')

        # Good state token
        state = serializer.dumps(
            {'app': 'test', 'sid': '1234',  'next': None, }
        )
        resp = client.get(
            url_for('invenio_oauthclient.rest_authorized', remote_app='test',
                    code='test', state=state)
        )
        assert resp.status_code == 200

        outdated_serializer = TimedJSONWebSignatureSerializer(
            app_rest.config['SECRET_KEY'],
            expires_in=0,
        )

        # Bad state - timeout
        state1 = outdated_serializer.dumps(
            {'app': 'test', 'sid': '1234',  'next': None, }
        )
        # Bad state - app
        state2 = serializer.dumps(
            # State for another existing app (test_invalid exists)
            {'app': 'test_invalid', 'sid': '1234',  'next': None, }
        )
        # Bad state - sid
        state3 = serializer.dumps(
            # State for another existing app (test_invalid exists)
            {'app': 'test', 'sid': 'bad',  'next': None, }
        )
        time.sleep(1)
        for s in [state1, state2, state3]:
            resp = client.get(
                url_for(
                    'invenio_oauthclient.rest_authorized', remote_app='test',
                    code='test', state=s)
            )
            assert resp.status_code == 302
            assert parse_qs(urlparse(resp.location).query)['code'][0] == '403'


def test_no_remote_app(app_rest):
    """Test no remote app."""
    with app_rest.test_client() as client:
        resp = client.get(
            url_for(
                'invenio_oauthclient.rest_authorized', remote_app='invalid')
        )
        assert resp.status_code == 404

        resp = client.get(
            url_for(
                'invenio_oauthclient.rest_disconnect', remote_app='invalid')
        )
        assert resp.status_code == 404

        resp = client.get(
            url_for('invenio_oauthclient.rest_signup', remote_app='invalid')
        )
        assert resp.status_code == 404


def test_token_getter_setter(app_rest, monkeypatch):
    """Test token getter setter."""
    # Mock session id
    monkeypatch.setattr('invenio_oauthclient._compat._create_identifier',
                        lambda: '1234')
    monkeypatch.setattr(
        'invenio_oauthclient.views.client._create_identifier', lambda: '1234')

    oauth = app_rest.extensions['oauthlib.client']

    # Mock user
    user = MagicMock()
    user.id = 1
    user.get_id = MagicMock(return_value=1)
    user.is_anonymous = False

    with app_rest.test_client() as c:
        login_user_via_session(c, user)
        # First call login to be redirected
        res = c.get(url_for('invenio_oauthclient.rest_login',
                            remote_app='full'))
        assert res.status_code == 302
        assert res.location.startswith(
            oauth.remote_apps['full'].authorize_url
        )
        state = parse_qs(urlparse(res.location).query)['state'][0]

        # Mock resposen class
        mock_response(app_rest.extensions['oauthlib.client'], 'full')

        # Imitate that the user authorized our request in the remote
        # application.
        c.get(url_for(
            'invenio_oauthclient.rest_authorized', remote_app='full',
            code='test', state=state,
        ))

        # Assert if everything is as it should be.
        from flask import session as flask_session
        assert flask_session['oauth_token_full'] == \
            ('test_access_token', '')

        t = RemoteToken.get(1, 'fullid')
        assert t.remote_account.client_id == 'fullid'
        assert t.access_token == 'test_access_token'
        assert RemoteToken.query.count() == 1

        # Mock a new authorized request
        mock_response(app_rest.extensions['oauthlib.client'], 'full', data={
            'access_token': 'new_access_token',
            'scope': "",
            'token_type': 'bearer'
        })

        c.get(url_for(
            'invenio_oauthclient.rest_authorized', remote_app='full',
            code='test', state=state
        ))

        t = RemoteToken.get(1, 'fullid')
        assert t.access_token == 'new_access_token'
        assert RemoteToken.query.count() == 1

        val = token_getter(
            app_rest.extensions['oauthlib.client'].remote_apps['full'])
        assert val == ('new_access_token', '')

        # Disconnect account
        res = c.get(url_for(
            'invenio_oauthclient.rest_disconnect', remote_app='full',
        ))
        assert res.status_code == 302
        expected_url_args = {
            "message": "Successfully disconnected.",
            "code": 200
        }
        check_response_redirect_url_args(res, expected_url_args)

        # Assert that remote account have been removed.
        t = RemoteToken.get(1, 'fullid')
        assert t is None
        # TODO: Figure out what is leaving session open & blocked
        db.session.close()


def test_rejected(app_rest, monkeypatch):
    """Test rejected."""
    # Mock session id
    monkeypatch.setattr('invenio_oauthclient._compat._create_identifier',
                        lambda: '1234')
    monkeypatch.setattr(
        'invenio_oauthclient.views.client._create_identifier', lambda: '1234')

    oauth = app_rest.extensions['oauthlib.client']

    # Mock user id
    user = MagicMock()
    user.get_id = MagicMock(return_value=1)
    user.is_authenticated = MagicMock(return_value=True)

    with app_rest.test_client() as c:
        login_user_via_session(c, user)
        # First call login to be redirected
        res = c.get(url_for('invenio_oauthclient.rest_login',
                            remote_app='full'))
        assert res.status_code == 302
        assert res.location.startswith(
            oauth.remote_apps['full'].authorize_url
        )

        # Mock response to imitate an invalid response. Here, an
        # example from GitHub when the code is expired.
        mock_response(
            app_rest.extensions['oauthlib.client'],
            'full',
            data=dict(
                error_uri='http://developer.github.com/v3/oauth/'
                '#bad-verification-code',
                error_description='The code passed is '
                'incorrect or expired.',
                error='bad_verification_code',
            )
        )

        # Imitate that the user authorized our request in the remote
        # application (however, the remote app will son reply with an
        # error)
        state = serializer.dumps({
            'app': 'full', 'sid': '1234',  'next': None,
        })
        res = c.get(url_for(
            'invenio_oauthclient.rest_authorized', remote_app='full',
            code='test', state=state
        ))
        assert res.status_code == 302
