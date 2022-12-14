# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2016-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Test handlers."""

import pytest
from flask import session, url_for
from flask_login import current_user
from flask_oauthlib.client import OAuth as FlaskOAuth
from flask_security import login_user, logout_user
from flask_security.confirmable import _security
from helpers import check_redirect_location
from werkzeug.routing import BuildError

from invenio_oauthclient import InvenioOAuthClient, current_oauthclient
from invenio_oauthclient.errors import AlreadyLinkedError
from invenio_oauthclient.handlers import (
    authorized_signup_handler,
    disconnect_handler,
    oauth_error_handler,
    signup_handler,
    token_session_key,
    token_setter,
)
from invenio_oauthclient.models import RemoteToken
from invenio_oauthclient.utils import oauth_authenticate
from invenio_oauthclient.views.client import blueprint as blueprint_client
from invenio_oauthclient.views.settings import blueprint as blueprint_settings


def test_authorized_signup_handler(remote, app, models_fixture):
    """Test authorized signup handler."""
    datastore = app.extensions["invenio-accounts"].datastore
    user = datastore.find_user(email="existing@inveniosoftware.org")

    example_response = {"access_token": "test_access_token"}

    # Mock remote app's handler
    current_oauthclient.signup_handlers[remote.name] = {
        "setup": lambda token, resp: None
    }

    # Authenticate user
    oauth_authenticate("dev", user)

    # Mock next url
    next_url = "/test/redirect"
    session[token_session_key(remote.name) + "_next_url"] = next_url

    # Check user is redirected to next_url
    resp = authorized_signup_handler(example_response, remote)
    check_redirect_location(resp, next_url)


def test_unauthorized_signup(remote, app, models_fixture):
    """Test unauthorized redirect on signup callback handler."""
    datastore = app.extensions["invenio-accounts"].datastore
    existing_email = "existing@inveniosoftware.org"
    user = datastore.find_user(email=existing_email)

    example_response = {"access_token": "test_access_token"}
    example_account_info = {
        "user": {
            "email": existing_email,
            "external_id": "1234",
            "external_method": "test_method",
        }
    }

    # Mock remote app's handler
    current_oauthclient.signup_handlers[remote.name] = {
        "info": lambda resp: example_account_info,
    }

    _security.confirmable = True
    _security.login_without_confirmation = False
    user.confirmed_at = None
    app.config["OAUTHCLIENT_REMOTE_APPS"][remote.name] = {}

    resp = authorized_signup_handler(example_response, remote)
    check_redirect_location(resp, lambda x: x.startswith("/login/"))


def test_signup_handler(remote, app, models_fixture):
    """Test signup handler."""
    datastore = app.extensions["invenio-accounts"].datastore
    existing_email = "existing@inveniosoftware.org"
    user = datastore.find_user(email=existing_email)

    # Already authenticated
    login_user(user)
    assert current_user.is_authenticated
    resp1 = signup_handler(remote)
    check_redirect_location(resp1, "/")
    logout_user()
    assert not current_user.is_authenticated

    # No OAuth token
    resp2 = signup_handler(remote)
    check_redirect_location(resp2, "/")

    # Not coming from authorized request
    token = RemoteToken.create(user.id, "testkey", "mytoken", "mysecret")
    token_setter(remote, token, "mysecret")
    with pytest.raises(BuildError):
        signup_handler(remote)


def test_already_linked_exception(app):
    """Test error when service is already linked to another account."""

    @oauth_error_handler
    def mock_handler(resp, remote):
        raise AlreadyLinkedError(None, None)

    resp = mock_handler(None, None)
    check_redirect_location(resp, "/account/settings/linkedaccounts/")


def test_unauthorized_disconnect(app, remote):
    """Test disconnect handler when user is not authenticated."""
    resp = disconnect_handler(remote)
    check_redirect_location(resp, lambda x: x.startswith("/login/"))


def test_dummy_handler(base_app):
    """Test dummy handler."""

    # Force usage of dummy handlers
    base_app.config["OAUTHCLIENT_REMOTE_APPS"]["github"]["signup_handler"] = {}

    # Initialize InvenioOAuth
    FlaskOAuth(base_app)
    InvenioOAuthClient(base_app)
    base_app.register_blueprint(blueprint_client)
    base_app.register_blueprint(blueprint_settings)

    # Try to sign-up client
    base_app.test_client().get(
        url_for("invenio_oauthclient.signup", remote_app="github", next="/someurl/")
    )
