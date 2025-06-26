# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2025 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Test case for EOSC AAI oauth remote app."""

from urllib.parse import parse_qs, urlparse

from flask import session, url_for
from flask_login import current_user
from flask_security import login_user
from flask_security.utils import hash_password
from helpers import get_state, mock_remote_get, mock_response
from invenio_accounts.models import User
from invenio_db import db

from invenio_oauthclient.contrib.eosc_aai import account_info
from invenio_oauthclient.handlers import token_session_key
from invenio_oauthclient.models import RemoteAccount, RemoteToken, UserIdentity


class MockResponse:
    """Mock response object for userinfo endpoint."""

    def __init__(self, data, status=200):
        self.data = data
        self.status = status


def test_account_info(app, example_eosc_aai):
    """Test account info extraction."""
    client = app.test_client()
    ioc = app.extensions["oauthlib.client"]
    # Ensure remote apps have been loaded (due to before first request)
    client.get(url_for("invenio_oauthclient.login", remote_app="eosc_aai"))

    example_data, example_account_info = example_eosc_aai

    # Mock userinfo endpoint response
    userinfo_data = {
        "sub": "28c5353b8bb34984a8bd4169ba94c606@eosc-federation.eu",
        "name": "Jane Doe",
        "given_name": "Jane",
        "family_name": "Doe",
        "email": "jane.doe@example.org",
        "eunode_projects": [
            "pp-0190356a-ac97-db53-21c0-df7cd31a47c4",
            "gp-01903568-c385-49ba-0356-1b4ac60a90ec",
            "gp-0190356b-25a5-4f61-f926-38f9e0cd541a",
        ],
        "entitlements": [
            "urn:geant:eosc-federation.eu:group:pp-0190356a-ac97-db53-21c0-df7cd31a47c4",
            "urn:geant:eosc-federation.eu:group:gp-01903568-c385-49ba-0356-1b4ac60a90ec:role=owner",
            "urn:geant:eosc-federation.eu:group:gp-0190356b-25a5-4f61-f926-38f9e0cd541a:role=member",
        ],
    }
    userinfo_response = MockResponse(userinfo_data, 200)
    mock_remote_get(ioc, "eosc_aai", userinfo_response)

    # Test with token response (ID token) data - profile info should come from userinfo
    token_data = {"sub": "28c5353b8bb34984a8bd4169ba94c606@eosc-federation.eu"}

    result = account_info(ioc.remote_apps["eosc_aai"], token_data)

    # Verify the result
    assert result == example_account_info

    # Verify that the original token_data has been updated with userinfo data
    assert token_data["name"] == "Jane Doe"
    assert token_data["email"] == "jane.doe@example.org"

    # Test empty userinfo response fallback
    empty_userinfo_response = MockResponse({}, 200)
    mock_remote_get(ioc, "eosc_aai", empty_userinfo_response)

    assert account_info(ioc.remote_apps["eosc_aai"], {}) == dict(
        external_id=None,
        external_method="eosc_aai",
        user=dict(
            email=None,
            profile=dict(
                full_name=None,
            ),
        ),
        active=True,
    )

    # Test userinfo failure with JWT fallback
    failed_userinfo_response = MockResponse({}, 500)
    mock_remote_get(ioc, "eosc_aai", failed_userinfo_response)

    # Create a mock JWT token
    import jwt

    jwt_payload = {
        "sub": "28c5353b8bb34984a8bd4169ba94c606@eosc-federation.eu",
        "email": "jane.doe@example.org",
        "name": "Jane Doe",
    }
    mock_jwt_token = jwt.encode(jwt_payload, "secret", algorithm="HS256")

    # Test with JWT fallback
    resp_with_jwt = {"id_token": mock_jwt_token}
    result = account_info(ioc.remote_apps["eosc_aai"], resp_with_jwt)

    assert (
        result["external_id"] == "28c5353b8bb34984a8bd4169ba94c606@eosc-federation.eu"
    )
    assert result["user"]["email"] == "jane.doe@example.org"
    assert result["user"]["profile"]["full_name"] == "Jane Doe"


def test_login(app):
    """Test EOSC AAI login."""
    client = app.test_client()

    resp = client.get(
        url_for("invenio_oauthclient.login", remote_app="eosc_aai", next="/someurl/")
    )
    assert resp.status_code == 302

    params = parse_qs(urlparse(resp.location).query)
    assert params["response_type"] == ["code"]
    assert params["scope"] == ["openid profile email entitlements"]
    assert params["redirect_uri"]
    assert params["client_id"]
    assert params["state"]


def test_authorized_signup(app_with_userprofiles, example_eosc_aai):
    """Test authorized callback with sign-up."""
    app = app_with_userprofiles
    example_data, _ = example_eosc_aai

    # Create OAuth token response format with user info
    oauth_token_response = {
        "access_token": "test_access_token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "test_refresh_token",
        "scope": "openid profile email",
        # OpenID Connect includes user claims in token response
        **example_data,
    }

    with app.test_client() as c:
        # Ensure remote apps have been loaded
        resp = c.get(url_for("invenio_oauthclient.login", remote_app="eosc_aai"))
        assert resp.status_code == 302

        # Mock the response from EOSC AAI
        mock_response(
            app.extensions["oauthlib.client"], "eosc_aai", oauth_token_response
        )

        # Mock userinfo endpoint response
        userinfo_data = {
            "sub": "28c5353b8bb34984a8bd4169ba94c606@eosc-federation.eu",
            "name": "Jane Doe",
            "given_name": "Jane",
            "family_name": "Doe",
            "email": "jane.doe@example.org",
            "eunode_projects": [
                "pp-0190356a-ac97-db53-21c0-df7cd31a47c4",
                "gp-01903568-c385-49ba-0356-1b4ac60a90ec",
                "gp-0190356b-25a5-4f61-f926-38f9e0cd541a",
            ],
            "entitlements": [
                "urn:geant:eosc-federation.eu:group:pp-0190356a-ac97-db53-21c0-df7cd31a47c4",
                "urn:geant:eosc-federation.eu:group:gp-01903568-c385-49ba-0356-1b4ac60a90ec:role=owner",
                "urn:geant:eosc-federation.eu:group:gp-0190356b-25a5-4f61-f926-38f9e0cd541a:role=member",
            ],
        }
        userinfo_response = MockResponse(userinfo_data, 200)
        mock_remote_get(
            app.extensions["oauthlib.client"], "eosc_aai", userinfo_response
        )

        # User authorized the requests and is redirect back
        resp = c.get(
            url_for(
                "invenio_oauthclient.authorized",
                remote_app="eosc_aai",
                code="test",
                state=get_state("eosc_aai"),
            )
        )
        assert resp.status_code == 302

        # Check that user is redirected to signup page
        assert resp.location == url_for(
            "invenio_oauthclient.signup", remote_app="eosc_aai"
        )


def test_authorized_signup_complete_flow(app_with_userprofiles, example_eosc_aai):
    """Test complete authorized callback with sign-up flow."""
    app = app_with_userprofiles
    example_data, _ = example_eosc_aai
    example_email = "jane.doe@example.org"

    # Create OAuth token response format with user info
    oauth_token_response = {
        "access_token": "test_access_token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "test_refresh_token",
        "scope": "openid profile email",
        # OpenID Connect includes user claims in token response
        **example_data,
    }

    with app.test_client() as c:
        # Ensure remote apps have been loaded
        c.get(url_for("invenio_oauthclient.login", remote_app="eosc_aai"))

        # Mock the response from EOSC AAI
        mock_response(
            app.extensions["oauthlib.client"], "eosc_aai", oauth_token_response
        )

        # Mock userinfo endpoint response
        userinfo_data = {
            "sub": "28c5353b8bb34984a8bd4169ba94c606@eosc-federation.eu",
            "name": "Jane Doe",
            "given_name": "Jane",
            "family_name": "Doe",
            "email": "jane.doe@example.org",
            "eunode_projects": [
                "pp-0190356a-ac97-db53-21c0-df7cd31a47c4",
                "gp-01903568-c385-49ba-0356-1b4ac60a90ec",
                "gp-0190356b-25a5-4f61-f926-38f9e0cd541a",
            ],
            "entitlements": [
                "urn:geant:eosc-federation.eu:group:pp-0190356a-ac97-db53-21c0-df7cd31a47c4",
                "urn:geant:eosc-federation.eu:group:gp-01903568-c385-49ba-0356-1b4ac60a90ec:role=owner",
                "urn:geant:eosc-federation.eu:group:gp-0190356b-25a5-4f61-f926-38f9e0cd541a:role=member",
            ],
        }
        userinfo_response = MockResponse(userinfo_data, 200)
        mock_remote_get(
            app.extensions["oauthlib.client"], "eosc_aai", userinfo_response
        )

        # User authorized the requests and is redirect back
        resp = c.get(
            url_for(
                "invenio_oauthclient.authorized",
                remote_app="eosc_aai",
                code="test",
                state=get_state("eosc_aai"),
            )
        )
        assert resp.status_code == 302
        assert resp.location == url_for(
            "invenio_oauthclient.signup", remote_app="eosc_aai"
        )

        # User loads sign-up page
        resp = c.get(url_for("invenio_oauthclient.signup", remote_app="eosc_aai"))
        assert resp.status_code == 200

        # Get account info from session
        account_info = session[token_session_key("eosc_aai") + "_account_info"]

        # User fills form to register
        data = {
            "email": example_email,
            "password": "test123456",
            "profile.username": "janedoe",
            "profile.full_name": account_info["user"]["profile"]["full_name"],
            "profile.affiliations": "EOSC",
        }

        # User submits signup form
        resp = c.post(
            url_for("invenio_oauthclient.signup", remote_app="eosc_aai"),
            data=data,
        )
        assert resp.status_code == 302

        # Assert database state (Sign-up complete)
        user = User.query.filter_by(email=example_email).one()

        # Check UserIdentity was created
        UserIdentity.query.filter_by(
            method="eosc_aai", id_user=user.id, id=example_data["sub"]
        ).one()

        # Check RemoteAccount was created
        remote_account = RemoteAccount.query.filter_by(user_id=user.id).one()

        # Check RemoteToken was created
        RemoteToken.query.filter_by(id_remote_account=remote_account.id).one()

        # Check user profile data
        assert user.user_profile["full_name"] == "Jane Doe"
        assert user.active
        # EOSC AAI is configured with auto_confirm=False, so user needs confirmation
        assert user.confirmed_at is None

        # Check EOSC AAI specific data is stored
        assert remote_account.extra_data["sub"] == example_data["sub"]
        assert (
            remote_account.extra_data["eunode_projects"]
            == example_data["eunode_projects"]
        )
        assert remote_account.extra_data["entitlements"] == example_data["entitlements"]

        # Test disconnect - should not work as it's the only login method
        resp = c.get(url_for("invenio_oauthclient.disconnect", remote_app="eosc_aai"))
        assert resp.status_code == 400

        # Verify account still exists
        user = User.query.filter_by(email=example_email).one()
        assert (
            1
            == UserIdentity.query.filter_by(
                method="eosc_aai", id_user=user.id, id=example_data["sub"]
            ).count()
        )

        # Set a password for the user
        user.password = hash_password("1234")
        db.session.commit()

        # Now disconnect should work
        resp = c.get(url_for("invenio_oauthclient.disconnect", remote_app="eosc_aai"))
        assert resp.status_code == 302

        # User still exists but OAuth connection is removed
        user = User.query.filter_by(email=example_email).one()
        assert (
            0
            == UserIdentity.query.filter_by(
                method="eosc_aai", id_user=user.id, id=example_data["sub"]
            ).count()
        )
        assert RemoteAccount.query.filter_by(user_id=user.id).count() == 0
        assert RemoteToken.query.count() == 0


def test_authorized_reject(app):
    """Test a rejected authorization request."""
    with app.test_client() as c:
        c.get(url_for("invenio_oauthclient.login", remote_app="eosc_aai"))

        # User denies authorization
        resp = c.get(
            url_for(
                "invenio_oauthclient.authorized",
                remote_app="eosc_aai",
                error="access_denied",
                error_description="User denied access",
                state=get_state("eosc_aai"),
            )
        )
        assert resp.status_code in (301, 302)
        assert resp.location == "/"

        assert session["_flashes"][0][0] == "info"


def test_authorized_already_authenticated(app, models_fixture, example_eosc_aai):
    """Test authorized callback when user is already authenticated."""
    datastore = app.extensions["invenio-accounts"].datastore
    login_manager = app.login_manager

    example_data, _ = example_eosc_aai
    existing_email = "existing@inveniosoftware.org"
    user = datastore.find_user(email=existing_email)

    @login_manager.user_loader
    def load_user(user_id):
        return user

    @app.route("/foo_login")
    def login():
        login_user(user)
        return "Logged In"

    # Create OAuth token response format with user info
    oauth_token_response = {
        "access_token": "test_access_token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "test_refresh_token",
        "scope": "openid profile email",
        **example_data,
    }

    with app.test_client() as client:
        # Make a fake login
        client.get("/foo_login", follow_redirects=True)

        # Ensure remote apps have been loaded
        client.get(url_for("invenio_oauthclient.login", remote_app="eosc_aai"))

        # Mock access token request
        mock_response(
            app.extensions["oauthlib.client"], "eosc_aai", oauth_token_response
        )

        # Mock userinfo endpoint response
        userinfo_data = {
            "sub": "28c5353b8bb34984a8bd4169ba94c606@eosc-federation.eu",
            "name": "Jane Doe",
            "given_name": "Jane",
            "family_name": "Doe",
            "email": "jane.doe@example.org",
            "eunode_projects": [
                "pp-0190356a-ac97-db53-21c0-df7cd31a47c4",
                "gp-01903568-c385-49ba-0356-1b4ac60a90ec",
                "gp-0190356b-25a5-4f61-f926-38f9e0cd541a",
            ],
            "entitlements": [
                "urn:geant:eosc-federation.eu:group:pp-0190356a-ac97-db53-21c0-df7cd31a47c4",
                "urn:geant:eosc-federation.eu:group:gp-01903568-c385-49ba-0356-1b4ac60a90ec:role=owner",
                "urn:geant:eosc-federation.eu:group:gp-0190356b-25a5-4f61-f926-38f9e0cd541a:role=member",
            ],
        }
        userinfo_response = MockResponse(userinfo_data, 200)
        mock_remote_get(
            app.extensions["oauthlib.client"], "eosc_aai", userinfo_response
        )

        # User goes to 'Linked accounts' and clicks 'Connect'
        resp = client.get(
            url_for(
                "invenio_oauthclient.login", remote_app="eosc_aai", next="/someurl/"
            )
        )
        assert resp.status_code == 302

        # User authorized the requests and is redirected back
        resp = client.get(
            url_for(
                "invenio_oauthclient.authorized",
                remote_app="eosc_aai",
                code="test",
                state=get_state("eosc_aai"),
            )
        )
        assert resp.status_code == 302

        # Assert database state (Linking complete)
        u = User.query.filter_by(email=existing_email).one()

        # Check UserIdentity was created
        UserIdentity.query.filter_by(
            method="eosc_aai", id_user=u.id, id=example_data["sub"]
        ).one()

        # Check RemoteAccount was created
        remote_account = RemoteAccount.query.filter_by(user_id=u.id).one()

        # Check EOSC AAI data is stored
        assert remote_account.extra_data["sub"] == example_data["sub"]
        assert (
            remote_account.extra_data["eunode_projects"]
            == example_data["eunode_projects"]
        )

        # Disconnect link should work since user has other login methods
        resp = client.get(
            url_for("invenio_oauthclient.disconnect", remote_app="eosc_aai")
        )
        assert resp.status_code == 302

        # User exists but EOSC AAI link is removed
        u = User.query.filter_by(email=existing_email).one()
        assert (
            0
            == UserIdentity.query.filter_by(
                method="eosc_aai", id_user=u.id, id=example_data["sub"]
            ).count()
        )


def test_not_authenticated(app):
    """Test disconnect when user is not authenticated."""
    with app.test_client() as client:
        assert not current_user.is_authenticated
        resp = client.get(
            url_for("invenio_oauthclient.disconnect", remote_app="eosc_aai")
        )
        assert resp.status_code == 302


def test_project_entitlements_extraction(example_eosc_aai):
    """Test that EOSC AAI specific claims are properly extracted."""
    example_data, _ = example_eosc_aai

    # Test project extraction
    projects = example_data.get("eunode_projects", [])
    assert len(projects) == 3
    assert "pp-0190356a-ac97-db53-21c0-df7cd31a47c4" in projects  # Personal project
    assert "gp-01903568-c385-49ba-0356-1b4ac60a90ec" in projects  # Group project 1
    assert "gp-0190356b-25a5-4f61-f926-38f9e0cd541a" in projects  # Group project 2

    # Test entitlements extraction
    entitlements = example_data.get("entitlements", [])
    assert len(entitlements) == 3

    # Check specific entitlement formats
    assert any("role=owner" in ent for ent in entitlements)
    assert any("role=member" in ent for ent in entitlements)
    assert any("pp-" in ent for ent in entitlements)  # Personal project
    assert any("gp-" in ent for ent in entitlements)  # Group project
