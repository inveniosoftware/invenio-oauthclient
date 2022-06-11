# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2016-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Test utils."""

import sys

import pytest
from flask_security.confirmable import _security
from invenio_db import db
from six.moves.urllib.parse import quote_plus

from invenio_oauthclient.errors import AlreadyLinkedError
from invenio_oauthclient.models import RemoteAccount, RemoteToken
from invenio_oauthclient.proxies import current_oauthclient
from invenio_oauthclient.utils import (
    _get_external_id,
    create_csrf_disabled_registrationform,
    create_registrationform,
    fill_form,
    filter_user_info,
    get_safe_redirect_target,
    oauth_authenticate,
    oauth_get_user,
    oauth_link_external_id,
    oauth_unlink_external_id,
    obj_or_import_string,
    patch_dictionary,
    rebuild_access_tokens,
)


def test_utilities(app, models_fixture):
    """Test utilities."""
    datastore = app.extensions["invenio-accounts"].datastore
    assert obj_or_import_string("invenio_oauthclient.errors")

    # User
    existing_email = "existing@inveniosoftware.org"
    user = datastore.find_user(email=existing_email)

    # Authenticate
    assert not _get_external_id({})
    assert not oauth_authenticate("dev", user, require_existing_link=True)

    _security.confirmable = True
    _security.login_without_confirmation = False
    user.confirmed_at = None
    assert not oauth_authenticate("dev", user)

    # Tokens
    t = RemoteToken.create(user.id, "dev", "mytoken", "mysecret")
    assert RemoteToken.get(
        user.id, "dev", access_token="mytoken"
    ) == RemoteToken.get_by_token("dev", "mytoken")

    assert oauth_get_user("dev", access_token=t.access_token) == user
    assert (
        oauth_get_user("dev", account_info={"user": {"email": existing_email}}) == user
    )

    # Link user to external id
    external_id = {"id": "123", "method": "test_method"}
    oauth_link_external_id(user, external_id)

    with pytest.raises(AlreadyLinkedError):
        oauth_link_external_id(user, external_id)

    assert (
        oauth_get_user(
            "dev",
            account_info={
                "external_id": external_id["id"],
                "external_method": external_id["method"],
            },
        )
        == user
    )

    # Cleanup
    oauth_unlink_external_id(external_id)
    acc = RemoteAccount.get(user.id, "dev")
    acc.delete()


def test_rebuilding_access_tokens(app, models_fixture):
    """Test rebuilding access tokens with random new SECRET_KEY."""
    old_secret_key = app.secret_key

    datastore = app.extensions["invenio-accounts"].datastore
    existing_email = "existing@inveniosoftware.org"
    user = datastore.find_user(email=existing_email)

    # Creating a new remote token and commiting to the db
    test_token = "mytoken"
    token_type = "testing"
    with db.session.begin_nested():
        rt = RemoteToken.create(
            user.id, "testkey", test_token, app.secret_key, token_type
        )
        db.session.add(rt)
    db.session.commit()

    # Changing application SECRET_KEY
    app.secret_key = "NEW_SECRET_KEY"
    db.session.expunge_all()

    # Asserting the decoding error occurs with the stale SECRET_KEY
    if sys.version_info[0] < 3:  # python 2
        remote_token = RemoteToken.query.first()
        assert remote_token.access_token != test_token
    else:  # python 3
        with pytest.raises(ValueError):
            RemoteToken.query.first()

    db.session.expunge_all()
    rebuild_access_tokens(old_secret_key)
    remote_token = RemoteToken.query.filter_by(token_type=token_type).first()

    # Asserting the access_token is not changed after rebuilding
    assert remote_token.access_token == test_token


def test_app_registrationform_missing_csrf(app, form_test_data):
    """App with CSRF disabled, registration form should not have it."""
    filled_form = _fill_form(app, create_registrationform, form_test_data)

    assert "profile" not in filled_form
    _assert_no_csrf_token(filled_form)


def test_app_registrationform_has_csrf(app_with_csrf, form_test_data):
    """App with CSRF enabled, test if registration form has it."""
    filled_form = _fill_form(app_with_csrf, create_registrationform, form_test_data)
    assert "profile" not in filled_form
    _assert_csrf_token(filled_form)


def test_registrationform_disable_csrf(app_with_csrf, form_test_data):
    """App with CSRF enabled, test if registration form removes it."""
    remote_apps = current_oauthclient.oauth.remote_apps
    first_remote_app = list(remote_apps.values())[0]
    filled_form = _fill_form(
        app_with_csrf,
        create_csrf_disabled_registrationform,
        form_test_data,
        remote=first_remote_app,
    )

    assert "profile" not in filled_form
    _assert_no_csrf_token(filled_form)


def test_registrationform_userprofile_missing_csrf(
    app_with_userprofiles, form_test_data
):
    """App with CSRF disabled and UserProfile, reg. form should not have it."""
    filled_form = _fill_form(
        app_with_userprofiles, create_registrationform, form_test_data
    )

    assert "profile" in filled_form
    assert "csrf_token" not in filled_form.profile
    _assert_no_csrf_token(filled_form)


def test_app_registrationform_userprofile_has_csrf(
    app_with_userprofiles_csrf, form_test_data
):
    """App with CSRF enabled and UserProfile, test if reg. form removes it."""
    filled_form = _fill_form(
        app_with_userprofiles_csrf, create_registrationform, form_test_data
    )

    assert "profile" in filled_form
    assert "csrf_token" not in filled_form.profile
    _assert_csrf_token(filled_form)


def test_registrationform_userprofile_disable_csrf(
    app_with_userprofiles_csrf, form_test_data
):
    """App with CSRF enabled and UserProfile, test if reg. form removes it."""
    remote_apps = current_oauthclient.oauth.remote_apps
    first_remote_app = list(remote_apps.values())[0]
    filled_form = _fill_form(
        app_with_userprofiles_csrf,
        create_csrf_disabled_registrationform,
        form_test_data,
        remote=first_remote_app,
    )

    assert "profile" in filled_form
    assert "csrf_token" not in filled_form.profile
    _assert_no_csrf_token(filled_form)


@pytest.mark.parametrize(
    "test_input,expected",
    [
        (
            "https://invenio.org/search?page=1&q=&keywords=taxonomy&keywords=animali",
            "/search?page=1&q=&keywords=taxonomy&keywords=animali",
        ),
        ("/search?page=1&size=20", "/search?page=1&size=20"),
        ("https://localhost/search?page=1", "https://localhost/search?page=1"),
        # previously encoded parameter
        (
            "/oauth/authorize?redirect_uri=http%3A%2F%2F127.0.0.1%3A5100%2Fauthorize",
            "/oauth/authorize?redirect_uri=http://127.0.0.1:5100/authorize",
        ),
    ],
)
def test_get_safe_redirect_target(app, test_input, expected):
    with app.test_request_context("/?next={0}".format(quote_plus(test_input))):
        assert get_safe_redirect_target() == expected


def _assert_csrf_token(form):
    """Assert that the field `csrf_token` exists in the form."""
    assert "csrf_token" in form
    assert form.csrf_token


def _assert_no_csrf_token(form):
    """Assert that the field `csrf_token` does not exist in the form."""

    # Flask-WTF==0.13.1 adds always `csrf_token` field, but with None value
    # Flask-WTF>0.14.2 do not `csrf_token` field
    assert "csrf_token" not in form or form.csrf_token.data is None


def _fill_form(app, form, data, *form_args, **form_kwargs):
    """Fill the input form with the provided data."""
    with app.test_request_context():
        filled_form = fill_form(form(*form_args, **form_kwargs), data)

        filled_form.validate()

        return filled_form


def test_patch_dictionary():
    """Test the dictionary patch function."""
    orig_dict = {
        "email": "user@inveniosoftware.org",
        "username": "user",
    }

    # patch some existing properties, add new ones, and leave some as is
    patch_dict = {
        "email": "admin@inveniosoftware.org",
        "profile": {
            "full_name": "Test User",
        },
        "extra": [1, 2, 3],
    }

    expected = {
        "email": "admin@inveniosoftware.org",
        "username": "user",
        "profile": {
            "full_name": "Test User",
        },
        "extra": [1, 2, 3],
    }

    patch_dictionary(orig_dict, patch_dict)
    assert orig_dict == expected


def test_precedence_mask(app):
    """Test if the precedence mask configuration is read properly."""
    precedence_mask = {
        "email": True,
        "password": False,
        "profile": {
            "username": True,
            "full_name": False,
            "extra1": True,
            "extra2": True,
            "extra3": False,
        },
    }

    user_info = {
        "email": "user@inveniosoftware.org",
        "password": "somepassword",
        "profile": {
            "username": "test-user",
            "full_name": "Test User",
            "extra2": 2,
            "extra3": 3,
            "extra4": 4,
        },
    }

    expected_filtered_user_info = {
        "email": "user@inveniosoftware.org",
        "profile": {
            "username": "test-user",
            "extra2": 2,
            "extra4": 4,
        },
    }

    input_values = {
        "email": "admin@inveniosoftware.org",
        "password": "anotherpassword",
        "profile": {
            "username": "admin",
            "full_name": "Ruler of the World",
            "extra2": 0,
            "extra3": 0,
        },
    }

    expected_values = {
        "email": "user@inveniosoftware.org",
        "password": "anotherpassword",
        "profile": {
            "username": "test-user",
            "full_name": "Ruler of the World",
            "extra2": 2,
            "extra3": 0,
            "extra4": 4,
        },
    }

    filter_user_info(user_info, precedence_mask)

    assert user_info == expected_filtered_user_info

    patch_dictionary(input_values, user_info)

    assert input_values == expected_values
