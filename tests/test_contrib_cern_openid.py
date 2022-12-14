# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2016-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Test case for CERN oauth remote app."""

import os

import pytest
from flask import g, session, url_for
from flask_security import login_user, logout_user
from flask_security.utils import hash_password
from helpers import get_state, mock_remote_get, mock_response
from six.moves.urllib_parse import parse_qs, urlparse

from invenio_oauthclient.contrib.cern_openid import (
    OAUTHCLIENT_CERN_OPENID_SESSION_KEY,
    account_info,
    disconnect_handler,
    fetch_extra_data,
    get_dict_from_response,
)

from flask_oauthlib.client import OAuthResponse  # noqa isort:skip


@pytest.fixture()
def example_cern_openid(request):
    """CERN openid example data."""
    file_path = os.path.join(
        os.path.dirname(__file__), "data/cern_openid_response_content.json"
    )
    with open(file_path) as response_file:
        json_data = response_file.read()

    from jwt import encode

    token = encode(dict(name="John Doe"), key="1234")
    return (
        OAuthResponse(resp=None, content=json_data, content_type="application/json"),
        dict(
            access_token=token,
            token_type="bearer",
            expires_in=1199,
            refresh_token="test_refresh_token",
        ),
        dict(
            user=dict(
                email="john.doe@cern.ch",
                profile=dict(username="jdoe", full_name="John Doe"),
            ),
            external_id="222222",
            external_method="cern_openid",
            active=True,
        ),
    )


def test_fetch_extra_data(app, example_cern_openid):
    """Test extra data extraction."""
    example_response, example_token, _ = example_cern_openid
    res = get_dict_from_response(example_response)

    # Check that groups were hidden as required
    extra_data = fetch_extra_data(res)

    assert "person_id" in extra_data
    assert extra_data["person_id"] == "234567"


def test_account_info(app, example_cern_openid):
    """Test account info extraction."""
    client = app.test_client()
    ioc = app.extensions["oauthlib.client"]

    # Ensure remote apps have been loaded (due to before first request)
    client.get(url_for("invenio_oauthclient.login", remote_app="cern_openid"))

    example_response, _, example_account_info = example_cern_openid

    mock_remote_get(ioc, "cern_openid", example_response)

    assert account_info(ioc.remote_apps["cern_openid"], None) == example_account_info
    assert g.oauth_logged_in_with_remote == ioc.remote_apps["cern_openid"]


def test_account_setup(app, example_cern_openid, models_fixture):
    """Test account setup after login."""
    with app.test_client() as c:
        ioc = app.extensions["oauthlib.client"]

        # Ensure remote apps have been loaded (due to before first request)
        resp = c.get(url_for("invenio_oauthclient.login", remote_app="cern_openid"))
        assert resp.status_code == 302

        example_response, example_token, example_account_info = example_cern_openid

        mock_response(app.extensions["oauthlib.client"], "cern_openid", example_token)
        mock_remote_get(ioc, "cern_openid", example_response)

        resp = c.get(
            url_for(
                "invenio_oauthclient.authorized",
                remote_app="cern_openid",
                code="test",
                state=get_state("cern_openid"),
            )
        )
        assert resp.status_code == 302
        assert resp.location == ("/account/settings/" "linkedaccounts/")
        # 3 needs:
        # {
        #   Need(method='id', value=4),
        #   Need(method='role', value='cern_user'),
        #   Need(method='id', value='john.doe@cern.ch')
        # }
        assert len(g.identity.provides) == 3

    datastore = app.extensions["invenio-accounts"].datastore
    user = datastore.find_user(email="john.doe@cern.ch")
    user.password = hash_password("1234")
    assert user
    assert user.confirmed_at

    with app.test_request_context():
        resp = disconnect_handler(ioc.remote_apps["cern_openid"])
        # this will delete the RemoteAccount
        assert resp.status_code >= 300

        # simulate login (account_info fetch)
        g.oauth_logged_in_with_remote = ioc.remote_apps["cern_openid"]

        login_user(user)
        # 2 needs only:
        #   missing Need(method='role', value='cern_user') that was in RemoteAccount
        assert len(g.identity.provides) == 2

        logout_user()
        assert len(g.identity.provides) == 1
        assert "cern_resource" not in session
        assert OAUTHCLIENT_CERN_OPENID_SESSION_KEY not in session

        # Login again to test the disconnect handler
        g.oauth_logged_in_with_remote = ioc.remote_apps["cern_openid"]
        login_user(user)
        assert len(g.identity.provides) == 2

        disconnect_handler(ioc.remote_apps["cern_openid"])


def test_login(app):
    """Test CERN login."""
    client = app.test_client()

    resp = client.get(
        url_for("invenio_oauthclient.login", remote_app="cern_openid", next="/someurl/")
    )
    assert resp.status_code == 302

    params = parse_qs(urlparse(resp.location).query)
    assert params["response_type"], ["code"]
    assert params["redirect_uri"]
    assert params["client_id"]
    assert params["state"]


def test_authorized_reject(app):
    """Test a rejected request."""
    with app.test_client() as c:
        c.get(url_for("invenio_oauthclient.login", remote_app="cern_openid"))
        resp = c.get(
            url_for(
                "invenio_oauthclient.authorized",
                remote_app="cern_openid",
                error="access_denied",
                error_description="User denied access",
                state=get_state("cern_openid"),
            )
        )
        assert resp.status_code in (301, 302)
        assert resp.location == "/"
        # Check message flash
        assert session["_flashes"][0][0] == "info"


def test_account_info_not_allowed_account(app, example_cern_openid):
    """Test account info extraction."""
    client = app.test_client()

    app.config["OAUTHCLIENT_CERN_OPENID_ALLOWED_ROLES"] = ["another cern role"]
    ioc = app.extensions["oauthlib.client"]

    # Ensure remote apps have been loaded (due to before first request)
    client.get(url_for("invenio_oauthclient.login", remote_app="cern_openid"))

    example_response, _, example_account_info = example_cern_openid

    mock_remote_get(ioc, "cern_openid", example_response)

    resp = account_info(ioc.remote_apps["cern_openid"], None)
    assert resp.status_code == 302
    assert session["_flashes"][0][0] == "danger"
    assert session["_flashes"][0][1] == "CERN account not allowed."
