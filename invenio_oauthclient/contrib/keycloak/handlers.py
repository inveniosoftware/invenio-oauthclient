# -*- coding: utf-8 -*-
#
# Copyright (C) 2020-2021 TU Wien.
#
# Invenio-Keycloak is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""OAuthClient endpoint handlers for communication with Keycloak.

The handler functions provided in this module are tailored to communicate
with Keycloak using OpenID-Connect.
To use them, they must be referenced in a REMOTE_APP configuration dictionary,
e.g.:

.. code-block:: python

    KEYCLOAK_REMOTE_APP = {
        # ...

        "authorized_handler": "invenio_oauthclient.handlers"
                              ":authorized_signup_handler",
        "disconnect_handler": "invenio_keycloak.handlers"
                              ":disconnect_handler",
        "signup_handler": {
            "info": "invenio_keycloak.handlers:info_handler",
            "setup": "invenio_keycloak.handlers:setup_handler",
            "view": "invenio_oauthclient.handlers:signup_handler"
        },

        # ...
    }

"""

from flask import current_app, redirect, url_for
from flask_login import current_user
from invenio_db import db

from invenio_oauthclient import current_oauthclient
from invenio_oauthclient.handlers.rest import response_handler
from invenio_oauthclient.handlers.utils import require_more_than_one_external_account
from invenio_oauthclient.models import RemoteAccount
from invenio_oauthclient.oauth import oauth_link_external_id, oauth_unlink_external_id

from .helpers import get_user_info


def info_serializer_handler(remote, resp, token_user_info, user_info=None, **kwargs):
    """Serialize the account info response object.

    :param remote: The remote application.
    :param resp: The response of the `authorized` endpoint.
    :param token_user_info: The content of the authorization token response.
    :param user_info: The response of the `user info` endpoint.
    :returns: A dictionary with serialized user information.
    """
    # fill out the information required by
    # 'invenio-accounts' and 'invenio-userprofiles'.
    #
    # note: "external_id": `preferred_username` should also work,
    #       as it is seemingly not editable in Keycloak

    user_info = user_info or {}  # prevent errors when accessing None.get(...)

    email = token_user_info.get("email") or user_info["email"]
    full_name = token_user_info.get("name") or user_info.get("name")
    username = token_user_info.get("preferred_username") or user_info.get(
        "preferred_username"
    )

    return {
        "user": {
            "active": True,
            "email": email,
            "profile": {
                "full_name": full_name,
                "username": username,
            },
        },
        "external_id": token_user_info["sub"],
        "external_method": remote.name,
    }


def info_handler(remote, resp):
    """Retrieve remote account information for finding matching local users.

    :param remote: The remote application.
    :param resp: The response of the `authorized` endpoint.
    :returns: A dictionary with the user information.
    """
    token_user_info, user_info = get_user_info(remote, resp)

    handlers = current_oauthclient.signup_handlers[remote.name]
    # `remote` param automatically injected via `make_handler` helper
    return handlers["info_serializer"](resp, token_user_info, user_info)


def setup_handler(remote, token, resp):
    """Perform additional setup after the user has been logged in."""
    token_user_info, _ = get_user_info(remote, resp, from_token_only=True)

    with db.session.begin_nested():
        # fetch the user's Keycloak ID and set it in extra_data
        keycloak_id = token_user_info["sub"]
        token.remote_account.extra_data = {
            "keycloak_id": keycloak_id,
        }

        user = token.remote_account.user
        external_id = {"id": keycloak_id, "method": remote.name}

        # link account with external Keycloak ID
        oauth_link_external_id(user, external_id)


@require_more_than_one_external_account
def _disconnect(remote, *args, **kwargs):
    """Common logic for handling disconnection of remote accounts."""
    if not current_user.is_authenticated:
        return current_app.login_manager.unauthorized()

    account = RemoteAccount.get(
        user_id=current_user.get_id(), client_id=remote.consumer_key
    )

    keycloak_id = account.extra_data.get("keycloak_id")

    if keycloak_id:
        external_id = {"id": keycloak_id, "method": remote.name}

        oauth_unlink_external_id(external_id)

    if account:
        with db.session.begin_nested():
            account.delete()


def disconnect_handler(remote, *args, **kwargs):
    """Handle unlinking of the remote account."""
    _disconnect(remote, *args, **kwargs)
    return redirect(url_for("invenio_oauthclient_settings.index"))


def disconnect_rest_handler(remote, *args, **kwargs):
    """Handle unlinking of the remote account."""
    _disconnect(remote, *args, **kwargs)
    rconfig = current_app.config["OAUTHCLIENT_REST_REMOTE_APPS"][remote.name]
    redirect_url = rconfig["disconnect_redirect_url"]
    return response_handler(remote, redirect_url)
