# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015, 2016 CERN.
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

"""Test case for ORCID oauth remote app."""

from __future__ import absolute_import

import httpretty
from flask import session, url_for
from flask_login import _create_identifier
from flask_security.utils import login_user
from invenio_accounts.models import User
from mock import MagicMock
from six.moves.urllib_parse import parse_qs, urlparse

from invenio_oauthclient.contrib.orcid import account_info
from invenio_oauthclient.models import UserIdentity
from invenio_oauthclient.views.client import serializer


def mock_response(oauth, remote_app='test', data=None):
    """Mock the oauth response to use the remote."""
    oauth.remote_apps[remote_app].handle_oauth2_response = MagicMock(
        return_value=data
    )


def _get_state():
    return serializer.dumps({'app': 'orcid', 'sid': _create_identifier(),
                             'next': None, })


def test_account_info(app, example):
    """Test account info extraction."""
    client = app.test_client()
    ioc = app.extensions['oauthlib.client']
    # Ensure remote apps have been loaded (due to before first
    # request)
    client.get(url_for("invenio_oauthclient.login", remote_app='orcid'))

    example_data, example_account_info = example

    assert account_info(
        ioc.remote_apps['orcid'], example_data) == example_account_info

    assert account_info(ioc.remote_apps['orcid'], {}) == \
        dict(external_id=None,
             external_method="orcid",
             nickname=None)


def test_login(app, example):
    """Test ORCID login."""
    client = app.test_client()

    resp = client.get(
        url_for("invenio_oauthclient.login", remote_app='orcid',
                next='/someurl/')
    )
    assert resp.status_code == 302

    params = parse_qs(urlparse(resp.location).query)
    assert params['response_type'], ['code']
    assert params['show_login'] == ['true']
    assert params['scope'] == ['/authenticate']
    assert params['redirect_uri']
    assert params['client_id']
    assert params['state']


def test_authorized_signup(app, example, orcid_bio):
    """Test authorized callback with sign-up."""
    example_data, example_account_info = example
    example_email = "orcidtest@invenio-software.org"

    with app.test_client() as c:
        # Ensure remote apps have been loaded (due to before first
        # request)
        c.get(url_for("invenio_oauthclient.login", remote_app='orcid'))

        mock_response(app.extensions['oauthlib.client'], 'orcid', example_data)

        # User authorized the requests and is redirect back
        resp = c.get(
            url_for("invenio_oauthclient.authorized",
                    remote_app='orcid', code='test',
                    state=_get_state()))
        assert resp.status_code == 302
        assert resp.location == (
            "http://localhost" +
            url_for('invenio_oauthclient.signup', remote_app='orcid')
        )

        # User load sign-up page.
        resp = c.get(url_for('invenio_oauthclient.signup', remote_app='orcid'))
        assert resp.status_code == 200

        # Mock request to ORCID to get user bio.
        httpretty.enable()
        httpretty.register_uri(
            httpretty.GET,
            "http://orcid.org/{0}/orcid-bio".format(example_data['orcid']),
            body=orcid_bio,
            content_type="application/orcid+json; qs=2;charset=UTF-8",
        )

        # User fills in email address.
        resp = c.post(url_for('invenio_oauthclient.signup',
                              remote_app='orcid'),
                      data=dict(email=example_email))
        assert resp.status_code == 302
        httpretty.disable()

        # Assert database state (Sign-up complete)
        user = User.query.filter_by(email=example_email).one()
        UserIdentity.query.filter_by(
            method='orcid', id_user=user.id,
            id=example_data['orcid']
        ).one()
        # FIXME see contrib/orcid.py line 167
        #  assert user.given_names == "Josiah"
        #  assert user.family_name == "Carberry"
        # check that the user's email is not yet validated
        assert user.active
        # check that the validation email has been sent
        #  assert hasattr(locmem, 'outbox') and len(locmem.outbox) == 1

        # Disconnect link
        resp = c.get(
            url_for("invenio_oauthclient.disconnect", remote_app='orcid'))
        assert resp.status_code == 302

        # User exists
        user = User.query.filter_by(email=example_email).one()
        # UserIdentity removed.
        assert 0 == UserIdentity.query.filter_by(
            method='orcid', id_user=user.id,
            id=example_data['orcid']
        ).count()


def test_authorized_reject(app, example):
    """Test a rejected request."""
    with app.test_client() as c:
        c.get(url_for("invenio_oauthclient.login", remote_app='orcid'))
        resp = c.get(
            url_for("invenio_oauthclient.authorized",
                    remote_app='orcid', error='access_denied',
                    error_description='User denied access',
                    state=_get_state()))
        assert resp.status_code in (301, 302)
        assert resp.location == (
            "http://localhost/"
        )
        # Check message flash
        assert session['_flashes'][0][0] == 'info'


def test_authorized_already_authenticated(models_fixture, example, orcid_bio):
    """Test authorized callback with sign-up."""
    from invenio_oauthclient.models import UserIdentity
    from invenio_accounts.models import User

    app = models_fixture

    datastore = app.extensions['invenio-accounts'].datastore
    login_manager = app.login_manager

    example_data, example_account_info = example
    existing_email = "existing@invenio-software.org"
    user = datastore.find_user(email=existing_email)

    @login_manager.user_loader
    def load_user(user_id):
        return user

    @app.route('/foo_login')
    def login():
        login_user(user)
        return "Logged In"

    with app.test_client() as client:

        # make a fake login (using my login function)
        client.get('/foo_login', follow_redirects=True)

        # Ensure remote apps have been loaded (due to before first
        # request)
        client.get(url_for("invenio_oauthclient.login", remote_app='orcid'))

        # Mock access token request
        mock_response(app.extensions['oauthlib.client'], 'orcid', example_data)

        # Mock request to ORCID to get user bio.
        httpretty.enable()
        httpretty.register_uri(
            httpretty.GET,
            "https://pub.orcid.org/v1.2/{0}/orcid-bio".format(
                example_data['orcid']),
            body=orcid_bio,
            content_type="application/orcid+json; qs=2;charset=UTF-8",
        )

        # User then goes to "Linked accounts" and clicks "Connect"
        resp = client.get(
            url_for("invenio_oauthclient.login", remote_app='orcid',
                    next='/someurl/')
        )
        assert resp.status_code == 302

        # User authorized the requests and is redirected back
        resp = client.get(
            url_for("invenio_oauthclient.authorized",
                    remote_app='orcid', code='test',
                    state=_get_state()))
        httpretty.disable()

        # Assert database state (Sign-up complete)
        u = User.query.filter_by(email=existing_email).one()
        UserIdentity.query.filter_by(
            method='orcid', id_user=u.id,
            id=example_data['orcid']
        ).one()
        # FIXME see contrib/orcid.py line 167
        # assert u.given_names == "Josiah"
        # assert u.family_name == "Carberry"

        # Disconnect link
        resp = client.get(
            url_for("invenio_oauthclient.disconnect", remote_app='orcid'))
        assert resp.status_code == 302

        # User exists
        u = User.query.filter_by(email=existing_email).one()
        # UserIdentity removed.
        assert 0 == UserIdentity.query.filter_by(
            method='orcid', id_user=u.id,
            id=example_data['orcid']
        ).count()
        assert 0 == UserIdentity.query.filter_by(
            method='orcid', id_user=u.id,
            id=example_data['orcid']
        ).count()
