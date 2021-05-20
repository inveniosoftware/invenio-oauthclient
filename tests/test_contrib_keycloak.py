# -*- coding: utf-8 -*-
#
# Copyright (C) 2020 FAIR Data Austria.
#
# Invenio-Keycloak is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Tests for the Keycloak OAuth remote_app."""

import httpretty
import jwt
import pytest
from flask import session, url_for
from flask_login import current_user, login_user
from flask_security.utils import hash_password
from helpers import get_state, mock_keycloak
from invenio_accounts.models import User
from invenio_db import db
from six.moves.urllib_parse import parse_qs, urlparse

from invenio_oauthclient.contrib.keycloak.helpers import _format_public_key, \
    get_user_info
from invenio_oauthclient.errors import OAuthError
from invenio_oauthclient.models import UserIdentity

# - - - - - - - - - - - - - -#
# Tests for Keycloak contrib #
# - - - - - - - - - - - - - -#


def test_login(app):
    """Test Keycloak login."""
    keycloak_config = app.config["OAUTHCLIENT_REMOTE_APPS"]["keycloak"]
    auth_url = keycloak_config["params"]["authorize_url"]

    client = app.test_client()

    resp = client.get(
        url_for(
            "invenio_oauthclient.login",
            remote_app="keycloak",
            next="/someurl/"
        )
    )

    assert resp.status_code == 302

    comps = urlparse(resp.location)
    params = parse_qs(comps.query)
    url = "{}://{}{}".format(comps.scheme, comps.netloc, comps.path)

    assert url == auth_url
    assert params["response_type"] == ["code"]
    assert params["scope"] == ["openid"]
    assert params["redirect_uri"]
    assert params["client_id"]
    assert params["state"]


@httpretty.activate
def test_authorized_signup_valid_user(app_with_userprofiles,
                                      example_keycloak_token,
                                      example_keycloak_userinfo,
                                      example_keycloak_realm_info):
    """Test authorized callback with sign-up."""
    app = app_with_userprofiles
    example_keycloak = example_keycloak_userinfo.data

    with app.test_client() as c:
        # ensure that remote_apps have been initialized (before first request)
        resp = c.get(
            url_for("invenio_oauthclient.login", remote_app="keycloak")
        )
        assert resp.status_code == 302

        # mock a running keycloak instance
        mock_keycloak(app.config,
                      example_keycloak_token,
                      example_keycloak,
                      example_keycloak_realm_info)

        # user authorized the request and is redirected back
        resp = c.get(
            url_for(
                "invenio_oauthclient.authorized", remote_app="keycloak",
                code="test", state=get_state("keycloak")
            )
        )

        # note: because we provided an e-mail address in 'info_handler',
        #       the user does not need to sign up
        assert resp.status_code == 302
        assert resp.location == ("http://localhost/"
                                 "account/settings/linkedaccounts/")

        # check that the user exists
        user = User.query.filter_by(email=example_keycloak["email"]).one()
        assert user is not None
        assert user.email == example_keycloak["email"]
        assert user.profile.full_name == "Max Moser"
        assert user.active

        # check that the user has a linked Keycloak account
        uid = UserIdentity.query.filter_by(
            method="keycloak",
            id_user=user.id,
            id=example_keycloak["sub"]
        ).one()
        assert uid.user is user

        # try to disconnect the Keycloak account again
        # which shouldn't work, because it's the user's only means of login
        resp = c.get(
            url_for("invenio_oauthclient.disconnect", remote_app="keycloak")
        )

        assert resp.status_code == 400

        # check that the user still exists
        user = User.query.filter_by(email=example_keycloak["email"]).one()
        assert user is not None

        # check that the Keycloak account hasn't been unlinked
        count = UserIdentity.query.filter_by(
            method="keycloak",
            id_user=user.id,
            id=example_keycloak["sub"]
        ).count()
        assert count == 1

        # set a password for the user
        user.password = hash_password("1234")
        db.session.commit()

        # try to disconnect the Keycloak account again
        resp = c.get(
            url_for("invenio_oauthclient.disconnect", remote_app="keycloak")
        )

        assert resp.status_code == 302

        # check that the user still exists
        user = User.query.filter_by(email=example_keycloak["email"]).one()
        assert user is not None

        # check that the Keycloak account hasn't been unlinked
        count = UserIdentity.query.filter_by(
            method="keycloak",
            id_user=user.id,
            id=example_keycloak["sub"]
        ).count()
        assert count == 0


def test_authorized_reject(app, example_keycloak_token):
    """Test a rejected request."""
    with app.test_client() as c:
        c.get(url_for("invenio_oauthclient.login", remote_app="keycloak"))

        resp = c.get(
            url_for(
                "invenio_oauthclient.authorized", remote_app="keycloak",
                error="access_denied", error_description="User denied access",
                state=get_state("keycloak")
            )
        )

        assert resp.status_code in (301, 302)
        assert resp.location == "http://localhost/"

        # check message flash
        assert session["_flashes"][0][0] == "info"


@httpretty.activate
def test_authorized_already_authenticated(app,
                                          models_fixture,
                                          example_keycloak_token,
                                          example_keycloak_userinfo,
                                          example_keycloak_realm_info):
    """Test authorized callback with sign-in."""
    datastore = app.extensions["invenio-accounts"].datastore
    login_manager = app.login_manager

    example_keycloak = example_keycloak_userinfo.data
    existing_mail = "existing@inveniosoftware.org"
    user = datastore.find_user(email=existing_mail)

    @login_manager.user_loader
    def load_user(user_id):
        return user

    @app.route("/logmein")
    def login():
        login_user(user)
        return "Logged in"

    with app.test_client() as c:
        c.get("/logmein", follow_redirects=True)

        # ensure that remote apps have been loaded (before first request)
        c.get(url_for("invenio_oauthclient.login", remote_app="keycloak"))

        # mock a running keycloak instance
        mock_keycloak(app.config,
                      example_keycloak_token,
                      example_keycloak,
                      example_keycloak_realm_info)

        # user goes to 'linked accounts' and clicks 'connect' with Keycloak
        resp = c.get(
            url_for("invenio_oauthclient.login", remote_app="keycloak",
                    next="/someurl/")
        )

        assert resp.status_code == 302

        # the user logged in to Keycloak and authorized the request
        resp = c.get(
            url_for(
                "invenio_oauthclient.authorized", remote_app="keycloak",
                code="test", state=get_state("keycloak")
            )
        )

        # check if the Keycloak account has been linked to the user
        u = User.query.filter_by(email=existing_mail).one()
        UserIdentity.query.filter_by(
            method="keycloak",
            id_user=u.id,
            id=example_keycloak["sub"]
        ).one()

        # let the user hit the 'disconnect' button
        resp = c.get(
            url_for("invenio_oauthclient.disconnect", remote_app="keycloak")
        )
        assert resp.status_code == 302

        # check that the user still exists,
        # but the Keycloak account has been unlinked
        u = User.query.filter_by(email=existing_mail).one()
        count = UserIdentity.query.filter_by(
            method="keycloak",
            id_user=u.id,
            id=example_keycloak["sub"]
        ).count()
        assert count == 0


def test_not_authenticated(app):
    """Test disconnect when the user is not authenticated."""
    with app.test_client() as c:
        assert not current_user.is_authenticated
        resp = c.get(
            url_for('invenio_oauthclient.disconnect', remote_app='keycloak')
        )
        assert resp.status_code == 302

# - - - - - - - - - - - - - - - - - - #
# Tests for Keycloak helper functions #
# - - - - - - - - - - - - - - - - - - #


def test_format_public_key(example_keycloak_public_key):
    """Test if _format_public_key does roughly the right thing."""
    fmt_key = _format_public_key(example_keycloak_public_key)

    assert fmt_key != example_keycloak_public_key
    assert example_keycloak_public_key in fmt_key
    assert fmt_key.startswith("-----BEGIN PUBLIC KEY-----\n")
    assert fmt_key.endswith("\n-----END PUBLIC KEY-----")

    strip_key = fmt_key.lstrip("-----BEGIN PUBLIC KEY-----")
    strip_key = strip_key.rstrip("-----END PUBLIC KEY-----")
    strip_key = strip_key.strip()

    assert example_keycloak_public_key == strip_key


def test_format_public_key_idempotence(example_keycloak_public_key):
    """Test whether the _format_public_key function is idempotent."""
    fmt_once = _format_public_key(example_keycloak_public_key)
    fmt_twice = _format_public_key(fmt_once)
    fmt_thrice = _format_public_key(fmt_twice)

    assert fmt_once == fmt_twice == fmt_thrice


@httpretty.activate
def test_get_realm_key(app,
                       example_keycloak_token,
                       example_keycloak_userinfo,
                       example_keycloak_realm_info):
    """Test the mechanism for fetching the realm's public key."""
    mock_keycloak(app.config,
                  example_keycloak_token,
                  example_keycloak_userinfo.data,
                  example_keycloak_realm_info)


@httpretty.activate
def test_get_userinfo_from_token(app,
                                 example_keycloak_token,
                                 example_keycloak_userinfo,
                                 example_keycloak_realm_info):
    """Test the "id_token" extraction mechanism from Keycloak's response."""
    mock_keycloak(app.config,
                  example_keycloak_token,
                  dict(),
                  example_keycloak_realm_info)

    token = example_keycloak_token["id_token"]
    options = {"verify_signature": False}
    expected_result = jwt.decode(token, verify=False, options=options)

    with app.test_client() as c:
        # ensure that remote apps have been loaded (before first request)
        c.get(url_for("invenio_oauthclient.login", remote_app="keycloak"))
        remote = app.extensions["oauthlib.client"].remote_apps["keycloak"]

        # the OAuthClient has to get its token from this call
        c.get(
            url_for(
                "invenio_oauthclient.authorized", remote_app="keycloak",
                code="test", state=get_state("keycloak")
            )
        )

        user_info = get_user_info(remote, example_keycloak_token,
                                  fallback_to_endpoint=False,
                                  options={"verify_exp": False})

        assert user_info is not None
        assert user_info == expected_result


@httpretty.activate
def test_get_userinfo_from_endpoint(app,
                                    example_keycloak_token,
                                    example_keycloak_userinfo,
                                    example_keycloak_realm_info):
    """Test the "/userinfo" mechanism when the "id_token" mechanism fails."""
    mock_keycloak(app.config,
                  example_keycloak_token,
                  example_keycloak_userinfo.data,
                  example_keycloak_realm_info)

    with app.test_client() as c:
        # ensure that remote apps have been loaded (before first request)
        c.get(url_for("invenio_oauthclient.login", remote_app="keycloak"))

        remote = app.extensions["oauthlib.client"].remote_apps["keycloak"]

        # the OAuthClient has to get its token from this call
        c.get(
            url_for(
                "invenio_oauthclient.authorized", remote_app="keycloak",
                code="test", state=get_state("keycloak")
            )
        )

        # force the endpoint mechanism by not providing a token
        user_info = get_user_info(remote, None)

        assert user_info is not None
        assert user_info == example_keycloak_userinfo.data


def test_raise_on_invalid_app_name():
    """Test that the app name format is validated."""
    class FakeRemote:
        """Fake remote class."""
        def __init__(self, name):
            """Constructor."""
            self.name = name

    for invalid in ["i n v a l i d", "ke'c.ak"]:
        fr = FakeRemote(invalid)
        assert fr.name == invalid
        with pytest.raises(OAuthError):
            get_user_info(fr, None)
