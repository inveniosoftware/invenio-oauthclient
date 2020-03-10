# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2016-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Test handlers."""

from __future__ import absolute_import, print_function

import pytest
from flask import session, url_for
from flask_login import current_user
from flask_oauthlib.client import OAuth as FlaskOAuth
from flask_security import login_user, logout_user
from flask_security.confirmable import _security
from helpers import check_redirect_location
from werkzeug.routing import BuildError

from invenio_oauthclient import InvenioOAuthClient, current_oauthclient
from invenio_oauthclient.errors import AlreadyLinkedError, OAuthResponseError
from invenio_oauthclient.handlers import response_token_setter, token_getter
from invenio_oauthclient.models import RemoteToken
from invenio_oauthclient.utils import oauth_authenticate
from invenio_oauthclient.views.client import blueprint as blueprint_client
from invenio_oauthclient.views.settings import blueprint as blueprint_settings


def test_token_setter(app, remote):
    """Test token setter on response from OAuth server."""

    # OAuth1
    resp_oauth1 = {
        'name': 'Josiah Carberry',
        'expires_in': 3599,
        'oauth_token': 'test_access_token',
        'oauth_token_secret': 'test_refresh_token',
        'scope': '/authenticate',
        'token_type': 'bearer',
    }
    assert not response_token_setter(remote, resp_oauth1)

    # Bad request
    resp_bad = {
        'invalid': 'invalid',
    }
    with pytest.raises(OAuthResponseError):
        response_token_setter(remote, resp_bad)


def test_token_getter(remote, models_fixture, app):
    """Test token getter on response from OAuth server."""
    datastore = app.extensions['invenio-accounts'].datastore
    existing_email = 'existing@inveniosoftware.org'
    user = datastore.find_user(email=existing_email)

    # Missing RemoteToken
    oauth_authenticate('dev', user)
    assert not token_getter(remote)

    # Populated RemoteToken
    RemoteToken.create(user.id, 'testkey', 'mytoken', 'mysecret')
    oauth_authenticate('dev', user)
    assert token_getter(remote) == ('mytoken', 'mysecret')
