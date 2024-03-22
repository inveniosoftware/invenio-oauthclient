# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2016-2018 CERN.
# Copyright (C) 2024 Graz University of Technology.
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
from helpers import check_response_redirect_url_args
from invenio_accounts.models import Role
from invenio_accounts.proxies import current_datastore
from werkzeug.routing import BuildError

from invenio_oauthclient import InvenioOAuthClientREST, current_oauthclient
from invenio_oauthclient.errors import AlreadyLinkedError
from invenio_oauthclient.handlers import token_session_key, token_setter
from invenio_oauthclient.handlers.rest import (
    authorized_signup_handler,
    disconnect_handler,
    oauth_resp_remote_error_handler,
    response_handler_postmessage,
    signup_handler,
)
from invenio_oauthclient.models import RemoteToken
from invenio_oauthclient.oauth import oauth_authenticate
from invenio_oauthclient.views.client import rest_blueprint

REMOTE_APPS = ["github", "orcid", "globus"]


@pytest.fixture(scope="function")
def remote(request, app_rest):
    """Fixture to return a remote app by name."""
    oauth = current_oauthclient.oauth
    return oauth.remote_apps[request.param]


@pytest.mark.parametrize("remote", REMOTE_APPS, indirect=["remote"])
def test_authorized_signup_handler(remote, app_rest, models_fixture):
    """Test authorized signup handler."""
    datastore = app_rest.extensions["invenio-accounts"].datastore
    user = datastore.find_user(email="existing@inveniosoftware.org")
    existing_email = "existing@inveniosoftware.org"

    example_response = {"access_token": "test_access_token"}
    example_account_info = {
        "user": {
            "email": existing_email,
        },
        "external_id": "1234",
        "external_method": "test_method",
    }

    # Mock remote app's handler
    current_oauthclient.signup_handlers[remote.name] = {
        "setup": lambda token, resp: None,
        "info": lambda resp: example_account_info,
    }

    # Authenticate user
    oauth_authenticate("dev", user)

    # Mock next url
    next_url = "/test/redirect"
    session[token_session_key(remote.name) + "_next_url"] = next_url

    # Check user is redirected to next_url
    expected_url_args = {
        "message": "Successfully authorized.",
        "code": 200,
        "next_url": next_url,
    }
    resp = authorized_signup_handler(example_response, remote)
    check_response_redirect_url_args(resp, expected_url_args)


@pytest.mark.parametrize("remote", REMOTE_APPS, indirect=["remote"])
def test_groups_handler(remote, app_rest, models_fixture):
    """Test group handler."""
    datastore = app_rest.extensions["invenio-accounts"].datastore
    existing_email = "existing@inveniosoftware.org"
    user = datastore.find_user(email=existing_email)
    example_groups = [
        {
            "id": "rdm-developers",
            "name": "rdm-developers",
            "description": "People contributing to RDM.",
        },
        {
            "id": "existing-group-id",
            "name": "new-group-name",
            "description": "A previously existing group with a changed name",
        },
    ]

    example_response = {"access_token": "test_access_token"}
    example_account_info = {
        "user": {
            "email": existing_email,
        },
        "external_id": "1234",
        "external_method": "test_method",
    }

    # prepare previously existing role in the db
    assert 0 == Role.query.count()
    current_datastore.create_role(
        id=example_groups[1]["id"],
        name="previous-group-name",
        description=example_groups[1]["description"],
        is_managed=False,
    )
    current_datastore.commit()

    # Mock remote app's handler
    current_oauthclient.signup_handlers[remote.name] = {
        "info": lambda resp: example_account_info,
        "groups": lambda resp: example_groups,
    }

    _security.confirmable = True
    _security.login_without_confirmation = False
    user.confirmed_at = None

    authorized_signup_handler(example_response, remote)

    # Assert that the new group is created
    roles = Role.query.all()
    assert 2 == len(roles)

    role = Role.query.filter(Role.id == example_groups[0]["id"]).one()
    assert role.id == example_groups[0]["id"]
    assert role.name == example_groups[0]["name"]
    assert role.description == example_groups[0]["description"]

    # Assert that existing group is updated
    role = Role.query.filter(Role.id == example_groups[1]["id"]).one()
    assert role.id == example_groups[1]["id"]
    assert role.name == "new-group-name"
    assert role.description == example_groups[1]["description"]


@pytest.mark.parametrize("remote", REMOTE_APPS, indirect=["remote"])
def test_unauthorized_signup(remote, app_rest, models_fixture):
    """Test unauthorized redirect on signup callback handler."""
    datastore = app_rest.extensions["invenio-accounts"].datastore
    existing_email = "existing@inveniosoftware.org"
    user = datastore.find_user(email=existing_email)

    example_response = {"access_token": "test_access_token"}
    example_account_info = {
        "user": {
            "email": existing_email,
        },
        "external_id": "1234",
        "external_method": "test_method",
    }

    # Mock remote app's handler
    current_oauthclient.signup_handlers[remote.name] = {
        "info": lambda resp: example_account_info,
    }

    _security.confirmable = True
    _security.login_without_confirmation = False
    user.confirmed_at = None

    expected_url_args = {"message": "Unauthorized.", "code": 401}
    resp = authorized_signup_handler(example_response, remote)
    check_response_redirect_url_args(resp, expected_url_args)


@pytest.mark.parametrize("remote", REMOTE_APPS, indirect=["remote"])
def test_signup_handler(remote, app_rest, models_fixture):
    """Test signup handler."""
    datastore = app_rest.extensions["invenio-accounts"].datastore
    existing_email = "existing@inveniosoftware.org"
    user = datastore.find_user(email=existing_email)
    # Already authenticated
    login_user(user)
    assert current_user.is_authenticated
    resp1 = signup_handler(remote)
    expected_url_args = {"message": "Successfully signed up.", "code": 200}
    check_response_redirect_url_args(resp1, expected_url_args)
    logout_user()
    assert not current_user.is_authenticated

    # No OAuth token
    resp2 = signup_handler(remote)
    expected_url_args = {"message": "Token not found.", "code": 400}

    check_response_redirect_url_args(resp2, expected_url_args)

    # Not coming from authorized request
    token = RemoteToken.create(user.id, "testkey", "mytoken", "mysecret")
    token_setter(remote, token, "mysecret")
    with pytest.raises(BuildError):
        signup_handler(remote)


@pytest.mark.parametrize("remote", REMOTE_APPS, indirect=["remote"])
def test_already_linked_exception(remote, app_rest):
    """Test error when service is already linked to another account."""

    @oauth_resp_remote_error_handler
    def mock_handler(resp, remote):
        raise AlreadyLinkedError(None, None)

    resp = mock_handler(None, remote)
    expected_url_args = {
        "message": "External service is already linked to another account.",
        "code": 400,
    }
    check_response_redirect_url_args(resp, expected_url_args)


@pytest.mark.parametrize("remote", REMOTE_APPS, indirect=["remote"])
def test_unauthorized_disconnect(remote, app_rest):
    """Test disconnect handler when user is not authenticated."""

    def mock_unauthorized():
        return "Unauthorized"

    app_rest.login_manager.unauthorized = mock_unauthorized
    resp = disconnect_handler(remote)
    expected_url_args = {"message": "Unauthorized.", "code": 401}
    check_response_redirect_url_args(resp, expected_url_args)


@pytest.mark.parametrize("remote_name", REMOTE_APPS)
def test_dummy_handler(remote_name, base_app):
    """Test dummy handler."""

    signup_handler = base_app.config["OAUTHCLIENT_REST_REMOTE_APPS"][remote_name][
        "signup_handler"
    ]

    # Force usage of dummy handlers
    base_app.config["OAUTHCLIENT_REST_REMOTE_APPS"][remote_name]["signup_handler"] = {}

    # Initialize InvenioOAuth
    FlaskOAuth(base_app)
    InvenioOAuthClientREST(base_app)
    base_app.register_blueprint(rest_blueprint)

    # Try to sign-up client
    base_app.test_client().get(
        url_for(
            "invenio_oauthclient.rest_signup", remote_app=remote_name, next="/someurl/"
        )
    )

    base_app.config["OAUTHCLIENT_REST_REMOTE_APPS"][remote_name][
        "signup_handler"
    ] = signup_handler


@pytest.mark.parametrize("remote_name", REMOTE_APPS)
def test_response_handler(remote_name, base_app):
    """Test response handler."""

    def mock_response_handler(remote, url, payload):
        return remote.name

    # Force usage of dummy handlers
    base_app.config["OAUTHCLIENT_REST_REMOTE_APPS"][remote_name][
        "response_handler"
    ] = mock_response_handler

    # Initialize InvenioOAuth
    FlaskOAuth(base_app)
    InvenioOAuthClientREST(base_app)
    base_app.register_blueprint(rest_blueprint)

    # Try to sign-up client
    response = base_app.test_client().get(
        url_for("invenio_oauthclient.rest_signup", remote_app=remote_name)
    )
    assert remote_name in str(response.data)


@pytest.mark.parametrize("remote", REMOTE_APPS, indirect=["remote"])
def test_response_handler_with_postmessage(remote, base_app):
    """Test response handler with postmessage."""

    # Force usage of dummy handlers
    base_app.config["OAUTHCLIENT_REST_REMOTE_APPS"][remote.name][
        "response_handler"
    ] = response_handler_postmessage

    # Initialize InvenioOAuth
    FlaskOAuth(base_app)
    InvenioOAuthClientREST(base_app)
    # The `rest_blueprint` is already registered indirectly by the
    # `remote` fixture

    datastore = base_app.extensions["invenio-accounts"].datastore
    existing_email = "existing@inveniosoftware.org"
    user = datastore.find_user(email=existing_email)
    # Already authenticated
    login_user(user)

    assert current_user.is_authenticated

    response = signup_handler(remote)
    expected_message = "Successfully signed up."
    expected_status = "200"

    assert expected_message in response
    assert expected_status in response
    assert "window.opener.postMessage" in response
