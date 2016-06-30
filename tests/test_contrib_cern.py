# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2016 CERN.
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

"""Test case for CERN oauth remote app."""

from __future__ import absolute_import

from flask import session, url_for
from six.moves.urllib_parse import parse_qs, urlparse

import invenio_oauthclient.contrib.cern as cern
from invenio_oauthclient.contrib.cern import account_info, account_setup, \
    fetch_groups, get_dict_from_response
from invenio_oauthclient.models import RemoteToken

from .helpers import get_state, mock_remote_get


def test_fetch_groups(app, example_cern):
    """Test group extraction."""
    example_response, example_token, _ = example_cern
    res = get_dict_from_response(example_response)

    # Override hidden group configuration
    import re
    cern.CFG_EXTERNAL_AUTH_HIDDEN_GROUPS = ('hidden_group',)
    cern.CFG_EXTERNAL_AUTH_HIDDEN_GROUPS_RE = (re.compile(r'Group[1-3]'),)

    # Check that groups were hidden as required
    groups = fetch_groups(res['Group'])
    assert all(group in groups
               for group in ('Group{}'.format(i) for i in range(4, 6)))


def test_account_info(app, example_cern):
    """Test account info extraction."""
    client = app.test_client()
    ioc = app.extensions['oauthlib.client']

    # Ensure remote apps have been loaded (due to before first request)
    client.get(url_for("invenio_oauthclient.login", remote_app='cern'))

    example_response, _, example_account_info = example_cern

    mock_remote_get(ioc, 'cern', example_response)

    assert account_info(
        ioc.remote_apps['cern'], None) == example_account_info

    assert account_info(ioc.remote_apps['cern'], {}) == \
        dict(
            user=dict(
                email='test.account@cern.ch',
                profile={
                    'full_name': u'Test Account', 'username': u'taccount'
                },
            ),
            external_id='123456', external_method="cern",
            active=True
        )


def test_account_setup(app, example_cern, models_fixture):
    """Test account setup after login."""
    client = app.test_client()
    ioc = app.extensions['oauthlib.client']

    # Ensure remote apps have been loaded (due to before first request)
    client.get(url_for("invenio_oauthclient.login", remote_app='cern'))

    example_response, example_token, example_account_info = example_cern
    res = get_dict_from_response(example_response)

    mock_remote_get(ioc, 'cern', example_response)

    app = models_fixture
    datastore = app.extensions['invenio-accounts'].datastore
    user = datastore.find_user(email="existing@inveniosoftware.org")
    token = RemoteToken.create(
        user.id, 'client_id', example_token['access_token'], 'secret',
        token_type=example_token['token_type']
    )
    account_setup(ioc.remote_apps['cern'], token, None)


def test_login(app):
    """Test CERN login."""
    client = app.test_client()

    resp = client.get(
        url_for("invenio_oauthclient.login", remote_app='cern',
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
        c.get(url_for("invenio_oauthclient.login", remote_app='cern'))
        resp = c.get(
            url_for("invenio_oauthclient.authorized",
                    remote_app='cern', error='access_denied',
                    error_description='User denied access',
                    state=get_state('cern')))
        assert resp.status_code in (301, 302)
        assert resp.location == "http://localhost/"
        # Check message flash
        assert session['_flashes'][0][0] == 'info'
