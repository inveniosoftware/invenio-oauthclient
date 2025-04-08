# -*- coding: utf-8 -*-
#
# Copyright (C)
# 2024 BNL.
# 2024 JLab
# Invenio-cilogon is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.
# This test was taken from Keycloak test and modified to test cilogon.

"""Tests for the cilogon OAuth remote_app."""

from urllib.parse import parse_qs, urlparse

import httpretty
import jwt
import pytest
from flask import session, url_for
from flask_login import current_user, login_user
from flask_security.utils import hash_password
from helpers import get_state, mock_cilogon
from invenio_accounts.models import Role, User
from invenio_db import db

from invenio_oauthclient.contrib.cilogon.helpers import get_all_keys, get_user_info
from invenio_oauthclient.errors import OAuthError
from invenio_oauthclient.handlers import token_session_key
from invenio_oauthclient.models import UserIdentity

# - - - - - - - - - - - - - -#
# Tests for Cilogon contrib #
# - - - - - - - - - - - - - -#


def test_login(app):
    """Test cilogon login."""
    cilogon_config = app.config["OAUTHCLIENT_REMOTE_APPS"]["cilogon"]
    auth_url = cilogon_config["params"]["authorize_url"]

    client = app.test_client()

    resp = client.get(
        url_for("invenio_oauthclient.login", remote_app="cilogon", next="/someurl/")
    )

    assert resp.status_code == 302
    comps = urlparse(resp.location)
    params = parse_qs(comps.query)
    url = "{}://{}{}".format(comps.scheme, comps.netloc, comps.path)

    assert url == auth_url
    assert params["response_type"] == ["code"]
    assert params["scope"] == ["openid email org.cilogon.userinfo profile "]
    assert params["redirect_uri"]
    assert params["client_id"]
    assert params["state"]


@httpretty.activate
def test_authorized_signup_valid_user(
    app_with_userprofiles,
    example_cilogon_token,
    example_cilogon_userinfo,
    example_jwks_info,
):
    """Test authorized callback with sign-up."""
    app = app_with_userprofiles
    example_cilogon = example_cilogon_userinfo

    with app.test_client() as c:
        # ensure that remote_apps have been initialized (before first request)
        resp = c.get(url_for("invenio_oauthclient.login", remote_app="cilogon"))
        assert resp.status_code == 302

        # mock a running cilogon instance
        patcher = mock_cilogon(
            app.config,
            example_cilogon_token,
            example_cilogon_userinfo,
            example_jwks_info,
        )
        # user authorized the request and is redirected back
        resp = c.get(
            url_for(
                "invenio_oauthclient.authorized",
                remote_app="cilogon",
                code="test",
                state=get_state("cilogon"),
            )
        )

        # note: because we provided an e-mail address in 'info_handler',
        #       the user does not need to sign up
        assert resp.status_code == 302
        assert resp.location == (
            url_for("invenio_oauthclient.signup", remote_app="cilogon")
        )

        # User load sign-up page.
        resp = c.get(url_for("invenio_oauthclient.signup", remote_app="cilogon"))
        assert resp.status_code == 200
        account_info = session[token_session_key("cilogon") + "_account_info"]
        account_info["user"]["profile"]["username"] = "panta"
        data = {
            "email": account_info["user"]["email"],
            "profile.username": account_info["user"]["profile"]["username"],
            "profile.full_name": account_info["user"]["profile"]["full_name"],
            "profile.affiliations": "cern",
        }
        # User fills form to register
        resp = c.post(
            url_for("invenio_oauthclient.signup", remote_app="cilogon"),
            data=data,
        )

        assert resp.status_code == 302
        httpretty.disable()

        # check that the user exists
        user = User.query.filter_by(email=example_cilogon["email"]).one()
        assert user is not None
        assert user.email == example_cilogon["email"]
        assert user.user_profile["full_name"] == "Anil Panta"
        assert user.active
        assert user.confirmed_at
        # check that the user has a linked cilogon account
        uid = UserIdentity.query.filter_by(
            method="cilogon", id_user=user.id, id=example_cilogon["sub"]
        ).one()
        assert uid.user is user

        # Assert that the new group is created
        # single group is allowed
        roles = Role.query.all()
        true_role = app.config["OAUTHCLIENT_CILOGON_ALLOWED_ROLES"]
        assert len(roles) == len(true_role)

        # we set id as group name.
        role = Role.query.filter(Role.id == true_role[0]).one()
        assert role.id == true_role[0]
        assert role.name == true_role[0]

        # try to disconnect the cilogon account
        # which shouldn't work, because it's the user's only means of login
        resp = c.get(url_for("invenio_oauthclient.disconnect", remote_app="cilogon"))

        assert resp.status_code == 400

        # check that the user still exists
        user = User.query.filter_by(email=example_cilogon["email"]).one()
        assert user is not None

        # check that the cilogon account hasn't been unlinked
        count = UserIdentity.query.filter_by(
            method="cilogon", id_user=user.id, id=example_cilogon["sub"]
        ).count()
        assert count == 1

        # set a password for the user
        user.password = hash_password("1234")
        db.session.commit()

        # try to disconnect the cilogon account again
        resp = c.get(url_for("invenio_oauthclient.disconnect", remote_app="cilogon"))

        assert resp.status_code == 302

        # check that the user still exists
        user = User.query.filter_by(email=example_cilogon["email"]).one()
        assert user is not None

        # check that the cilogon account hasn't been unlinked
        count = UserIdentity.query.filter_by(
            method="cilogon", id_user=user.id, id=example_cilogon["sub"]
        ).count()
        assert count == 0
        patcher.stop()


@httpretty.activate
def test_authorized_signup_valid_user_without_userprofile(
    app,
    example_cilogon_token,
    example_cilogon_userinfo,
    example_jwks_info,
):
    """Test authorized callback with sign-up."""
    app = app
    example_cilogon = example_cilogon_userinfo

    with app.test_client() as c:
        # ensure that remote_apps have been initialized (before first request)
        resp = c.get(url_for("invenio_oauthclient.login", remote_app="cilogon"))
        assert resp.status_code == 302

        # mock a running cilogon instance
        patcher = mock_cilogon(
            app.config,
            example_cilogon_token,
            example_cilogon_userinfo,
            example_jwks_info,
        )
        # user authorized the request and is redirected back
        resp = c.get(
            url_for(
                "invenio_oauthclient.authorized",
                remote_app="cilogon",
                code="test",
                state=get_state("cilogon"),
            )
        )

        assert resp.status_code == 302
        # check that the user exists
        user = User.query.filter_by(email=example_cilogon["email"]).one()
        assert user is not None
        assert user.email == example_cilogon["email"]
        assert user.active
        assert user.confirmed_at
        # check that the user has a linked cilogon account
        uid = UserIdentity.query.filter_by(
            method="cilogon", id_user=user.id, id=example_cilogon["sub"]
        ).one()
        assert uid.user is user

        # Assert that the new group is created
        # single group is allowed
        roles = Role.query.all()
        true_role = app.config["OAUTHCLIENT_CILOGON_ALLOWED_ROLES"]
        assert len(roles) == len(true_role)
        patcher.stop()


@httpretty.activate
def test_authorized_signup_valid_allow_all_roles(
    app,
    example_cilogon_token,
    example_cilogon_userinfo,
    example_jwks_info,
):
    """Test authorized callback with sign-up and allow all roles"""
    app = app

    example_cilogon = example_cilogon_userinfo

    with app.test_client() as c:
        # ensure that remote_apps have been initialized (before first request)
        resp = c.get(url_for("invenio_oauthclient.login", remote_app="cilogon"))
        assert resp.status_code == 302

        # mock a running cilogon instance
        patcher = mock_cilogon(
            app.config,
            example_cilogon_token,
            example_cilogon_userinfo,
            example_jwks_info,
        )

        # allowing this to be True means no role check is done and
        # no group should be created
        app.config["OAUTHCLIENT_CILOGON_ALLOW_ANY_ROLES"] = True
        # user authorized the request and is redirected back
        resp = c.get(
            url_for(
                "invenio_oauthclient.authorized",
                remote_app="cilogon",
                code="test",
                state=get_state("cilogon"),
            )
        )
        assert resp.status_code == 302
        roles = Role.query.all()
        assert len(roles) == 0
        patcher.stop()


@httpretty.activate
def test_invalid_role_reject(
    app,
    example_cilogon_token,
    example_cilogon_userinfo,
    example_jwks_info,
):
    """Test authorized callback with sign-up and allow all roles"""
    app = app

    example_cilogon = example_cilogon_userinfo

    with app.test_client() as c:
        # ensure that remote_apps have been initialized (before first request)
        resp = c.get(url_for("invenio_oauthclient.login", remote_app="cilogon"))
        assert resp.status_code == 302

        # mock a running cilogon instance
        patcher = mock_cilogon(
            app.config,
            example_cilogon_token,
            example_cilogon_userinfo,
            example_jwks_info,
        )
        app.config["OAUTHCLIENT_CILOGON_ALLOWED_ROLES"] = ["random"]
        resp = c.get(
            url_for(
                "invenio_oauthclient.authorized",
                remote_app="cilogon",
                code="test",
                state=get_state("cilogon"),
            )
        )
        assert resp.status_code in (301, 302)
        assert resp.location == "/"
        assert session["_flashes"][0][0] == "danger"
        patcher.stop()


def test_authorized_reject(app, example_cilogon_token):
    """Test a rejected request."""
    with app.test_client() as c:
        c.get(url_for("invenio_oauthclient.login", remote_app="cilogon"))

        resp = c.get(
            url_for(
                "invenio_oauthclient.authorized",
                remote_app="cilogon",
                error="access_denied",
                error_description="User denied access",
                state=get_state("cilogon"),
            )
        )
        assert resp.status_code in (301, 302)
        assert resp.location == "/"

        # check message flash
        assert session["_flashes"][0][0] == "info"


def test_not_authenticated(app):
    """Test disconnect when the user is not authenticated."""
    with app.test_client() as c:
        assert not current_user.is_authenticated
        resp = c.get(url_for("invenio_oauthclient.disconnect", remote_app="cilogon"))
        assert resp.status_code == 302


@httpretty.activate
def test_authorized_already_authenticated(
    app,
    models_fixture,
    example_cilogon_token,
    example_cilogon_userinfo,
    example_jwks_info,
):
    """Test authorized callback with sign-in."""
    datastore = app.extensions["invenio-accounts"].datastore
    login_manager = app.login_manager

    example_cilogon = example_cilogon_userinfo
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
        c.get(url_for("invenio_oauthclient.login", remote_app="cilogon"))

        # mock a running cilogon instance
        mock_cilogon(
            app.config,
            example_cilogon_token,
            example_cilogon_userinfo,
            example_jwks_info,
        )

        # user goes to 'linked accounts' and clicks 'connect' with cilogon
        resp = c.get(
            url_for("invenio_oauthclient.login", remote_app="cilogon", next="/someurl/")
        )

        assert resp.status_code == 302

        # the user logged in to cilogon and authorized the request
        resp = c.get(
            url_for(
                "invenio_oauthclient.authorized",
                remote_app="cilogon",
                code="test",
                state=get_state("cilogon"),
            )
        )

        # check if the cilogon account has been linked to the user
        u = User.query.filter_by(email=existing_mail).one()
        UserIdentity.query.filter_by(
            method="cilogon", id_user=u.id, id=example_cilogon["sub"]
        ).one()

        # let the user hit the 'disconnect' button
        resp = c.get(url_for("invenio_oauthclient.disconnect", remote_app="cilogon"))
        assert resp.status_code == 302

        # check that the user still exists,
        # but the cilogon account has been unlinked
        u = User.query.filter_by(email=existing_mail).one()
        count = UserIdentity.query.filter_by(
            method="cilogon", id_user=u.id, id=example_cilogon["sub"]
        ).count()
        assert count == 0
