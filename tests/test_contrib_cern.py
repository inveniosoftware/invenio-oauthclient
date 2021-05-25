# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2016-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Test case for CERN oauth remote app."""

from flask import g, session, url_for
from flask_security import login_user, logout_user
from flask_security.utils import hash_password
from helpers import get_state, mock_remote_get, mock_response
from six.moves.urllib_parse import parse_qs, urlparse

from invenio_oauthclient.contrib.cern import OAUTHCLIENT_CERN_SESSION_KEY, \
    account_info, disconnect_handler, fetch_extra_data, fetch_groups, \
    get_dict_from_response


def test_fetch_groups(app, example_cern):
    """Test group extraction."""
    example_response, example_token, _ = example_cern
    res = get_dict_from_response(example_response)

    # Override hidden group configuration
    import re
    app.config['OAUTHCLIENT_CERN_HIDDEN_GROUPS'] = ('hidden_group',)
    app.config['OAUTHCLIENT_CERN_HIDDEN_GROUPS_RE'] = (
        re.compile(r'Group[1-3]'),
    )

    # Check that groups were hidden as required
    groups = fetch_groups(res['Group'])
    assert all(group in groups
               for group in ('Group{}'.format(i) for i in range(4, 6)))


def test_fetch_extra_data(app, example_cern):
    """Test extra data extraction."""
    example_response, example_token, _ = example_cern
    res = get_dict_from_response(example_response)

    # Check that groups were hidden as required
    extra_data = fetch_extra_data(res)

    assert 'person_id' in extra_data
    assert extra_data['person_id'] == "234567"
    assert 'identity_class' in extra_data
    assert extra_data['identity_class'] == "CERN Registered"
    assert 'department' in extra_data
    assert extra_data['department'] == "IT/CDA"


def test_fetch_extra_data_fields_missing(app, example_cern):
    """Test extra data extraction when fields are missing."""
    example_response, example_token, _ = example_cern
    res = get_dict_from_response(example_response)

    del res['PersonID']
    del res['IdentityClass']
    del res['Department']

    # Check that groups were hidden as required
    extra_data = fetch_extra_data(res)

    assert 'person_id' in extra_data
    assert extra_data['person_id'] is None
    assert 'identity_class' in extra_data
    assert extra_data['identity_class'] is None
    assert 'department' in extra_data
    assert extra_data['department'] is None


def test_account_info(app, example_cern):
    """Test account info extraction."""
    client = app.test_client()
    ioc = app.extensions['oauthlib.client']

    # Ensure remote apps have been loaded (due to before first request)
    client.get(url_for('invenio_oauthclient.login', remote_app='cern'))

    example_response, _, example_account_info = example_cern

    mock_remote_get(ioc, 'cern', example_response)

    assert account_info(
        ioc.remote_apps['cern'], None) == example_account_info
    assert g.oauth_logged_in_with_remote == ioc.remote_apps['cern']

    assert account_info(ioc.remote_apps['cern'], {}) == \
        dict(
            user=dict(
                email='test.account@cern.ch',
                profile={
                    'full_name': u'Test Account', 'username': u'taccount'
                },
            ),
            external_id='123456', external_method='cern',
            active=True
        )


def test_account_setup(app, example_cern, models_fixture):
    """Test account setup after login."""
    with app.test_client() as c:
        ioc = app.extensions['oauthlib.client']

        # Ensure remote apps have been loaded (due to before first request)
        resp = c.get(url_for('invenio_oauthclient.login', remote_app='cern'))
        assert resp.status_code == 302

        example_response, example_token, example_account_info = example_cern

        mock_response(app.extensions['oauthlib.client'], 'cern',
                      example_token)
        mock_remote_get(ioc, 'cern', example_response)

        resp = c.get(url_for(
            'invenio_oauthclient.authorized',
            remote_app='cern', code='test',
            state=get_state('cern')))
        assert resp.status_code == 302
        assert resp.location == ('http://localhost/account/settings/'
                                 'linkedaccounts/')
        assert len(g.identity.provides) == 7

    datastore = app.extensions['invenio-accounts'].datastore
    user = datastore.find_user(email='test.account@cern.ch')
    user.password = hash_password("1234")
    assert user

    with app.test_request_context():
        resp = disconnect_handler(ioc.remote_apps['cern'])
        assert resp.status_code >= 300

        # simulate login (account_info fetch)
        g.oauth_logged_in_with_remote = ioc.remote_apps['cern']

        login_user(user)
        assert len(g.identity.provides) == 7

        logout_user()
        assert len(g.identity.provides) == 1
        assert "cern_resource" not in session
        assert OAUTHCLIENT_CERN_SESSION_KEY not in session

        # Login again to test the disconnect handler
        g.oauth_logged_in_with_remote = ioc.remote_apps['cern']
        login_user(user)
        assert len(g.identity.provides) == 7

        disconnect_handler(ioc.remote_apps['cern'])


def test_login(app):
    """Test CERN login."""
    client = app.test_client()

    resp = client.get(
        url_for('invenio_oauthclient.login', remote_app='cern',
                next='/someurl/')
    )
    assert resp.status_code == 302

    params = parse_qs(urlparse(resp.location).query)
    assert params['response_type'], ['code']
    assert params['scope'] == ['Name Email Bio Groups']
    assert params['redirect_uri']
    assert params['client_id']
    assert params['state']


def test_authorized_reject(app):
    """Test a rejected request."""
    with app.test_client() as c:
        c.get(url_for('invenio_oauthclient.login', remote_app='cern'))
        resp = c.get(
            url_for('invenio_oauthclient.authorized',
                    remote_app='cern', error='access_denied',
                    error_description='User denied access',
                    state=get_state('cern')))
        assert resp.status_code in (301, 302)
        assert resp.location == 'http://localhost/'
        # Check message flash
        assert session['_flashes'][0][0] == 'info'


def test_account_info_not_allowed_account(app, example_cern):
    """Test account info extraction."""
    client = app.test_client()

    app.config['OAUTHCLIENT_CERN_ALLOWED_IDENTITY_CLASSES'] = [
        'another cern type'
    ]
    ioc = app.extensions['oauthlib.client']

    # Ensure remote apps have been loaded (due to before first request)
    client.get(url_for('invenio_oauthclient.login', remote_app='cern'))

    example_response, _, example_account_info = example_cern

    mock_remote_get(ioc, 'cern', example_response)

    resp = account_info(ioc.remote_apps['cern'], None)
    assert resp.status_code == 302
    assert session['_flashes'][0][0] == 'danger'
    assert session['_flashes'][0][1] == 'CERN account not allowed.'
