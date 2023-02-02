# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Test case for ORCID oauth remote app."""

import httpretty
from flask import session, url_for
from flask_login import current_user
from flask_security import login_user
from flask_security.utils import hash_password
from helpers import get_state, mock_response
from invenio_accounts.models import User
from invenio_db import db
from six.moves.urllib_parse import parse_qs, urlparse

from invenio_oauthclient.contrib.orcid import account_info
from invenio_oauthclient.handlers import token_session_key
from invenio_oauthclient.models import RemoteAccount, RemoteToken, UserIdentity


def test_account_info(app, example_orcid):
    """Test account info extraction."""
    client = app.test_client()
    ioc = app.extensions["oauthlib.client"]
    # Ensure remote apps have been loaded (due to before first
    # request)
    client.get(url_for("invenio_oauthclient.login", remote_app="orcid"))

    example_data, example_account_info = example_orcid

    assert account_info(ioc.remote_apps["orcid"], example_data) == example_account_info

    assert account_info(ioc.remote_apps["orcid"], {}) == dict(
        external_id=None,
        external_method="orcid",
        user=dict(profile=dict(full_name=None)),
    )


def test_login(app, example_orcid):
    """Test ORCID login."""
    client = app.test_client()

    resp = client.get(
        url_for("invenio_oauthclient.login", remote_app="orcid", next="/someurl/")
    )
    assert resp.status_code == 302

    params = parse_qs(urlparse(resp.location).query)
    assert params["response_type"], ["code"]
    assert params["show_login"] == ["true"]
    assert params["scope"] == ["/authenticate"]
    assert params["redirect_uri"]
    assert params["client_id"]
    assert params["state"]


def test_authorized_signup(app_with_userprofiles, example_orcid, orcid_bio):
    """Test authorized callback with sign-up."""
    app = app_with_userprofiles
    example_data, example_account_info = example_orcid
    example_email = "orcidtest@inveniosoftware.org"

    with app.test_client() as c:
        # Ensure remote apps have been loaded (due to before first
        # request)
        c.get(url_for("invenio_oauthclient.login", remote_app="orcid"))

        mock_response(app.extensions["oauthlib.client"], "orcid", example_data)

        # User authorized the requests and is redirect back
        resp = c.get(
            url_for(
                "invenio_oauthclient.authorized",
                remote_app="orcid",
                code="test",
                state=get_state("orcid"),
            )
        )
        assert resp.status_code == 302
        assert resp.location == (
            url_for("invenio_oauthclient.signup", remote_app="orcid")
        )

        # User load sign-up page.
        resp = c.get(url_for("invenio_oauthclient.signup", remote_app="orcid"))
        assert resp.status_code == 200

        account_info = session[token_session_key("orcid") + "_account_info"]
        data = {
            "email": example_email,
            "password": "123456",
            "profile.username": "pippo",
            "profile.full_name": account_info["user"]["profile"]["full_name"],
            "profile.affiliations": "CERN",
        }

        # Mock request to ORCID to get user bio.
        httpretty.enable()
        httpretty.register_uri(
            httpretty.GET,
            "http://orcid.org/{0}/orcid-bio".format(example_data["orcid"]),
            body=orcid_bio,
            content_type="application/orcid+json; qs=2;charset=UTF-8",
        )

        # User fills form to register
        resp = c.post(
            url_for("invenio_oauthclient.signup", remote_app="orcid"),
            data=data,
        )
        assert resp.status_code == 302
        httpretty.disable()

        # Assert database state (Sign-up complete)
        user = User.query.filter_by(email=example_email).one()
        UserIdentity.query.filter_by(
            method="orcid", id_user=user.id, id=example_data["orcid"]
        ).one()
        # FIXME see contrib/orcid.py line 167
        assert user.user_profile["full_name"] == "Josiah Carberry"
        #  assert user.given_names == 'Josiah'
        #  assert user.family_name == 'Carberry'
        # check that the user's email is not yet validated
        assert user.active
        # check that the validation email has been sent
        #  assert hasattr(locmem, 'outbox') and len(locmem.outbox) == 1
        assert not user.confirmed_at

        # Disconnect link
        # should not work, because it's the user's only means of login
        resp = c.get(url_for("invenio_oauthclient.disconnect", remote_app="orcid"))
        assert resp.status_code == 400

        user = User.query.filter_by(email=example_email).one()
        assert (
            1
            == UserIdentity.query.filter_by(
                method="orcid", id_user=user.id, id=example_data["orcid"]
            ).count()
        )

        # set a password for the user
        user.password = hash_password("1234")
        db.session.commit()

        # Disconnect again
        resp = c.get(url_for("invenio_oauthclient.disconnect", remote_app="orcid"))
        assert resp.status_code == 302

        # User exists
        user = User.query.filter_by(email=example_email).one()
        # UserIdentity removed.
        assert (
            0
            == UserIdentity.query.filter_by(
                method="orcid", id_user=user.id, id=example_data["orcid"]
            ).count()
        )
        assert RemoteAccount.query.filter_by(user_id=user.id).count() == 0
        assert RemoteToken.query.count() == 0


def test_authorized_reject(app, example_orcid):
    """Test a rejected request."""
    with app.test_client() as c:
        c.get(url_for("invenio_oauthclient.login", remote_app="orcid"))
        resp = c.get(
            url_for(
                "invenio_oauthclient.authorized",
                remote_app="orcid",
                error="access_denied",
                error_description="User denied access",
                state=get_state("orcid"),
            )
        )
        assert resp.status_code in (301, 302)
        assert resp.location == "/"
        # Check message flash
        assert session["_flashes"][0][0] == "info"


def test_authorized_already_authenticated(
    app, models_fixture, example_orcid, orcid_bio
):
    """Test authorized callback with sign-up."""
    datastore = app.extensions["invenio-accounts"].datastore
    login_manager = app.login_manager

    example_data, example_account_info = example_orcid
    existing_email = "existing@inveniosoftware.org"
    user = datastore.find_user(email=existing_email)

    @login_manager.user_loader
    def load_user(user_id):
        return user

    @app.route("/foo_login")
    def login():
        login_user(user)
        return "Logged In"

    with app.test_client() as client:
        # make a fake login (using my login function)
        client.get("/foo_login", follow_redirects=True)

        # Ensure remote apps have been loaded (due to before first
        # request)
        client.get(url_for("invenio_oauthclient.login", remote_app="orcid"))

        # Mock access token request
        mock_response(app.extensions["oauthlib.client"], "orcid", example_data)

        # Mock request to ORCID to get user bio.
        httpretty.enable()
        httpretty.register_uri(
            httpretty.GET,
            "https://pub.orcid.org/v1.2/{0}/orcid-bio".format(example_data["orcid"]),
            body=orcid_bio,
            content_type="application/orcid+json; qs=2;charset=UTF-8",
        )

        # User then goes to 'Linked accounts' and clicks 'Connect'
        resp = client.get(
            url_for("invenio_oauthclient.login", remote_app="orcid", next="/someurl/")
        )
        assert resp.status_code == 302

        # User authorized the requests and is redirected back
        resp = client.get(
            url_for(
                "invenio_oauthclient.authorized",
                remote_app="orcid",
                code="test",
                state=get_state("orcid"),
            )
        )
        httpretty.disable()

        # Assert database state (Sign-up complete)
        u = User.query.filter_by(email=existing_email).one()
        UserIdentity.query.filter_by(
            method="orcid", id_user=u.id, id=example_data["orcid"]
        ).one()
        # FIXME see contrib/orcid.py line 167
        # assert u.given_names == 'Josiah'
        # assert u.family_name == 'Carberry'

        # Disconnect link
        resp = client.get(url_for("invenio_oauthclient.disconnect", remote_app="orcid"))
        assert resp.status_code == 302

        # User exists
        u = User.query.filter_by(email=existing_email).one()
        # UserIdentity removed.
        assert (
            0
            == UserIdentity.query.filter_by(
                method="orcid", id_user=u.id, id=example_data["orcid"]
            ).count()
        )


def test_not_authenticated(app, models_fixture):
    """Test disconnect when user is not authenticated."""
    with app.test_client() as client:
        assert not current_user.is_authenticated
        resp = client.get(url_for("invenio_oauthclient.disconnect", remote_app="orcid"))
        assert resp.status_code == 302
