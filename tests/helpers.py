# SPDX-FileCopyrightText: 2015-2025 CERN.
# SPDX-License-Identifier: MIT

"""OAuth client test utility functions."""

import json
from inspect import isfunction
from urllib.parse import parse_qs, urlencode, urlparse

import httpretty
from flask import session
from mock import MagicMock

from invenio_oauthclient.views.client import serializer


def get_state(app="test"):
    """Get the latest Authlib protocol state for a remote app."""
    prefix = f"_state_{app}_"
    keys = [key for key in session if key.startswith(prefix)]
    assert keys
    return keys[-1][len(prefix) :]


def mock_response(oauth, remote_app="test", data=None):
    """Mock the token endpoint while retaining Authlib state validation."""
    data = data or {
        "access_token": "test_access_token",
        "scope": "",
        "token_type": "bearer",
    }
    oauth.remote_apps[remote_app]._fetch_oauth2_token = MagicMock(return_value=data)


def mock_remote_get(oauth, remote_app="test", data=None):
    """Mock the oauth remote get response."""
    oauth.remote_apps[remote_app].get = MagicMock(return_value=data)


def mock_remote_http_request(oauth, remote_app="test", data=None):
    """Mock the oauth remote get response."""
    oauth.remote_apps[remote_app].http_request = MagicMock(return_value=data)


def check_redirect_location(resp, loc):
    """Check response redirect location."""
    assert resp._status_code == 302
    if isinstance(loc, str):
        assert resp.headers["Location"] == loc
    elif isfunction(loc):
        assert loc(resp.headers["Location"])


def check_response_redirect_url(client, response, expected_url):
    """Check application redirect state stored for an OAuth request."""
    assert response.status_code == 302
    state = parse_qs(urlparse(response.location).query)["state"][0]
    with client.session_transaction() as session:
        signed_state = session[f"oauthclient_state_{state}"]
    assert serializer.loads(signed_state)["next"] == expected_url


def check_response_redirect_url_args(response, expected_args):
    """Check response redirect url."""
    assert response.status_code == 302
    assert urlencode(expected_args) == urlparse(response.location).query


def mock_keycloak(app_config, token_dict, user_info_dict, realm_info):
    """Mock a running Keycloak instance."""
    app_config["OAUTHCLIENT_KEYCLOAK_USER_INFO_FROM_ENDPOINT"] = False
    keycloak_settings = app_config["OAUTHCLIENT_REMOTE_APPS"]["keycloak"]

    httpretty.register_uri(
        httpretty.POST,
        keycloak_settings["params"]["access_token_url"],
        body=json.dumps(token_dict),
        content_type="application/json",
    )

    httpretty.register_uri(
        httpretty.GET,
        app_config["OAUTHCLIENT_KEYCLOAK_USER_INFO_URL"],
        body=json.dumps(user_info_dict),
        content_type="application/json",
    )

    httpretty.register_uri(
        httpretty.GET,
        app_config["OAUTHCLIENT_KEYCLOAK_REALM_URL"],
        body=json.dumps(realm_info),
        content_type="application/json",
    )
