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

import httpretty
from flask import session, url_for
from flask_login import _create_identifier
from flask_security.utils import login_user
from six.moves.urllib_parse import parse_qs, urlparse

from invenio_accounts.models import User
from invenio_oauthclient.contrib.cern import account_info
from invenio_oauthclient.models import UserIdentity
from invenio_oauthclient.views.client import serializer

from .helpers import mock_response, mock_remote_get, get_state


def test_fetch_groups():
    """Test group extraction."""



def test_account_info(app, example_cern):
    """Test account info extraction."""
    client = app.test_client()
    ioc = app.extensions['oauthlib.client']
    # Ensure remote apps have been loaded (due to before first
    # request)
    client.get(url_for("invenio_oauthclient.login", remote_app='cern'))

    example_response, _, example_account_info = example_cern

    mock_remote_get(app.extensions['oauthlib.client'], 'cern', example_response)

    assert account_info(
        ioc.remote_apps['cern'], None) == example_account_info

    assert account_info(ioc.remote_apps['cern'], {}) == \
        dict(email='test.account@cern.ch',
             profile={'full_name': u'Test Account', 'nickname': u'taccount'},
             external_id='123456', external_method="cern",
             active=True)


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


def test_authorized_signup(app, example_cern):
    example_response, example_data, example_account_info = example_cern
    example_email = "cerntest@cern.ch"

    with app.test_client() as c:
        c.get(url_for("invenio_oauthclient.login", remote_app='cern'))

        mock_remote_get(
                app.extensions['oauthlib.client'], 'cern', example_response)
        mock_response(app.extensions['oauthlib.client'], 'cern', example_data)

        resp = c.get(
            url_for("invenio_oauthclient.authorized",
                    remote_app='cern', code='test',
                    state=get_state('cern')))
        assert resp.status_code == 302
        assert resp.location == ("http://localhost/" +
            url_for('invenio_oauthclient.signup', remote_app='cern')
        )

        resp = c.get(url_for('invenio_oauthclient.signup', remote_app='cern'))
        assert resp.status_code == 200


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

