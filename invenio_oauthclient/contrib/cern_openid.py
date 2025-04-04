# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2023 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Pre-configured remote application for enabling sign in/up with CERN.

1. Edit your configuration and add:

   .. code-block:: python

       import copy

       from invenio_oauthclient.contrib import cern_openid

       OAUTH_REMOTE_REST_APP = copy.deepcopy(cern_openid.REMOTE_REST_APP)
       # update any params if needed
       OAUTH_REMOTE_REST_APP["params"].update({})

       OAUTHCLIENT_REMOTE_APPS = dict(
           cern_openid=OAUTH_REMOTE_REST_APP,
       )
       OAUTHCLIENT_REST_REMOTE_APPS = dict(
           cern_openid=OAUTH_REMOTE_REST_APP,
       )
       CERN_APP_OPENID_CREDENTIALS = dict(
           consumer_key="changeme",
           consumer_secret="changeme",
       )
2. Register a new application with CERN OPENID visiting the page
   ``https://application-portal.web.cern.ch/``. When registering the
   application ensure that the *Redirect URI* points to:
   ``http://localhost:5000/api/oauth/authorized/cern_openid/``, if you have
   used the rest oauth application, or
   ``http://localhost:5000/oauth/authorized/cern_openid/`` (note, CERN
   does not allow localhost to be used, thus you need to follow the CERN OAUTH
   section in the common recipes in
   ``https://digital-repositories.web.cern.ch/digital-repositories``.
3. Grab the *Client ID* and *Client Secret* after registering the application
   and add them to your instance configuration (``invenio.cfg``):
   .. code-block:: python
       CERN_APP_OPENID_CREDENTIALS = dict(
           consumer_key="<CLIENT ID>",
           consumer_secret="<CLIENT SECRET>",
       )
4. Now login using CERN OAuth:
   - http://localhost:5000/oauth/login/cern/ , if you configure the UI oauth
     application.
   - http://localhost:5000/api/oauth/login/cern/ , if you configure the API
     oauth application.
5. Also, you should see CERN listed under Linked accounts:
   http://localhost:5000/account/settings/linkedaccounts/
By default the CERN module will try first look if a link already exists
between a CERN account and a user. If no link is found, the user is asked
to provide an email address to sign-up.
In templates you can add a sign in/up link:
.. code-block:: jinja
    <a href="{{ url_for("invenio_oauthclient.login",
      remote_app="cern_openid") }}">
      Sign in with CERN
    </a>
"""

from datetime import datetime, timedelta

from flask import Blueprint, current_app, flash, g, redirect, session, url_for
from flask_login import current_user
from flask_principal import (
    AnonymousIdentity,
    RoleNeed,
    UserNeed,
    identity_changed,
    identity_loaded,
)
from invenio_db import db
from invenio_i18n import gettext as _
from invenio_i18n import lazy_gettext
from jwt import decode

from invenio_oauthclient.errors import OAuthCERNRejectedAccountError
from invenio_oauthclient.handlers.rest import response_handler
from invenio_oauthclient.handlers.utils import require_more_than_one_external_account
from invenio_oauthclient.models import RemoteAccount
from invenio_oauthclient.oauth import oauth_link_external_id, oauth_unlink_external_id
from invenio_oauthclient.proxies import current_oauthclient

OAUTHCLIENT_CERN_OPENID_REFRESH_TIMEDELTA = timedelta(minutes=-5)
"""Default interval for refreshing CERN extra data (e.g. groups).

False value disabled the refresh.
"""

OAUTHCLIENT_CERN_OPENID_SESSION_KEY = "identity.cern_openid_provides"
"""Name of session key where CERN roles are stored."""

OAUTHCLIENT_CERN_OPENID_ALLOWED_ROLES = ["cern_user"]
"""CERN OAuth application role values that are allowed to be used."""

BASE_APP = dict(
    title=lazy_gettext("CERN"),
    description=lazy_gettext("Connecting to CERN Organization."),
    icon="",
    logout_url="https://auth.cern.ch/auth/realms/cern/protocol/"
    "openid-connect/logout",
    signup_options={
        "auto_confirm": True,
        "send_register_msg": False,
    },
    params=dict(
        base_url="https://auth.cern.ch/auth/realms/cern",
        request_token_url=None,
        access_token_url="https://auth.cern.ch/auth/realms/cern/protocol/"
        "openid-connect/token",
        access_token_method="POST",
        authorize_url="https://auth.cern.ch/auth/realms/cern/protocol/"
        "openid-connect/auth",
        app_key="CERN_APP_OPENID_CREDENTIALS",
        content_type="application/json",
    ),
)

REMOTE_APP = dict(BASE_APP)
REMOTE_APP.update(
    dict(
        authorized_handler="invenio_oauthclient.handlers:authorized_signup_handler",
        disconnect_handler="invenio_oauthclient.contrib.cern_openid:disconnect_handler",
        signup_handler=dict(
            info="invenio_oauthclient.contrib.cern_openid:account_info",
            setup="invenio_oauthclient.contrib.cern_openid:account_setup",
            view="invenio_oauthclient.handlers:signup_handler",
        ),
    )
)
"""CERN Openid Remote Application."""

REMOTE_REST_APP = dict(BASE_APP)
REMOTE_REST_APP.update(
    dict(
        authorized_handler="invenio_oauthclient.handlers.rest:authorized_signup_handler",
        disconnect_handler="invenio_oauthclient.contrib.cern_openid:disconnect_rest_handler",
        signup_handler=dict(
            info="invenio_oauthclient.contrib.cern_openid:account_info_rest",
            setup="invenio_oauthclient.contrib.cern_openid:account_setup",
            view="invenio_oauthclient.handlers.rest:signup_handler",
        ),
        response_handler=(
            "invenio_oauthclient.handlers.rest:default_remote_response_handler"
        ),
        authorized_redirect_url="/",
        disconnect_redirect_url="/",
        signup_redirect_url="/",
        error_redirect_url="/",
    )
)
"""CERN Openid Remote REST Application."""

OAUTHCLIENT_CERN_OPENID_USERINFO_URL = (
    "https://auth.cern.ch/auth/realms/cern/protocol/openid-connect/userinfo"
)

OAUTHCLIENT_CERN_OPENID_JWT_TOKEN_DECODE_PARAMS = dict(
    options=dict(
        verify_signature=False,
        verify_aud=False,
    ),
    algorithms=["HS256", "RS256"],
)

cern_oauth_blueprint = Blueprint("cern_openid_oauth", __name__)


def find_remote_by_client_id(client_id):
    """Return a remote application based with given client ID."""
    for remote in current_oauthclient.oauth.remote_apps.values():
        if remote.name == "cern_openid" and remote.consumer_key == client_id:
            return remote


def fetch_extra_data(resource):
    """Return a dict with extra data retrieved from CERN OAuth."""
    person_id = resource.get("cern_person_id")
    return dict(person_id=person_id)


def account_roles_and_extra_data(account, resource, refresh_timedelta=None):
    """Fetch account roles and extra data from resource if necessary."""
    updated = datetime.utcnow()
    modified_since = updated
    if refresh_timedelta is not None:
        modified_since += refresh_timedelta
    modified_since = modified_since.isoformat()
    last_update = account.extra_data.get("updated", modified_since)

    if last_update > modified_since:
        return account.extra_data.get("roles", [])

    roles = resource["cern_roles"]
    extra_data = current_app.config.get(
        "OAUTHCLIENT_CERN_OPENID_EXTRA_DATA_SERIALIZER", fetch_extra_data
    )(resource)

    account.extra_data.update(roles=roles, updated=updated.isoformat(), **extra_data)
    return roles


def extend_identity(identity, roles):
    """Extend identity with roles based on CERN groups."""
    provides = set([UserNeed(current_user.email)] + [RoleNeed(name) for name in roles])
    identity.provides |= provides
    key = current_app.config.get(
        "OAUTHCLIENT_CERN_OPENID_SESSION_KEY",
        OAUTHCLIENT_CERN_OPENID_SESSION_KEY,
    )
    session[key] = provides


def disconnect_identity(identity):
    """Disconnect identity from CERN groups."""
    session.pop("cern_resource", None)
    key = current_app.config.get(
        "OAUTHCLIENT_CERN_OPENID_SESSION_KEY",
        OAUTHCLIENT_CERN_OPENID_SESSION_KEY,
    )
    provides = session.pop(key, set())
    identity.provides -= provides


def get_dict_from_response(response):
    """Prepare new mapping with 'Value's grouped by 'Type'."""
    result = {}
    if getattr(response, "_resp") and response._resp.code > 400:
        return result

    for key, value in response.data.items():
        result.setdefault(key, value)
    return result


def get_resource(remote, token_response=None):
    """Query CERN Resources to get user info and roles."""
    cached_resource = session.pop("cern_resource", None)
    if cached_resource:
        return cached_resource

    url = current_app.config.get(
        "OAUTHCLIENT_CERN_OPENID_USERINFO_URL",
        OAUTHCLIENT_CERN_OPENID_USERINFO_URL,
    )
    response = remote.get(url)
    dict_response = get_dict_from_response(response)
    if token_response:
        decoding_params = current_app.config.get(
            "OAUTHCLIENT_CERN_OPENID_JWT_TOKEN_DECODE_PARAMS",
            OAUTHCLIENT_CERN_OPENID_JWT_TOKEN_DECODE_PARAMS,
        )
        token_data = decode(token_response["access_token"], **decoding_params)
        dict_response.update(token_data)
    session["cern_resource"] = dict_response
    return dict_response


def _account_info(remote, resp):
    """Retrieve remote account information used to find local user."""
    g.oauth_logged_in_with_remote = remote
    resource = get_resource(remote, resp)

    valid_roles = current_app.config.get(
        "OAUTHCLIENT_CERN_OPENID_ALLOWED_ROLES",
        OAUTHCLIENT_CERN_OPENID_ALLOWED_ROLES,
    )
    cern_roles = resource.get("cern_roles")
    if cern_roles is None or not set(cern_roles).issubset(valid_roles):
        raise OAuthCERNRejectedAccountError(
            _(
                "User roles %(cern_roles)s are not one of %(valid_roles)s",
                cern_roles=cern_roles,
                valid_roles=valid_roles,
            ),
            remote,
            resp,
        )

    email = resource["email"]
    external_id = resource["cern_upn"]
    nice = resource["preferred_username"]
    name = resource["name"]

    return dict(
        user=dict(email=email.lower(), profile=dict(username=nice, full_name=name)),
        external_id=external_id,
        external_method="cern_openid",
        active=True,
    )


def account_info(remote, resp):
    """Retrieve remote account information used to find local user."""
    try:
        return _account_info(remote, resp)
    except OAuthCERNRejectedAccountError as e:
        current_app.logger.warning(e.message, exc_info=True)
        flash(_("CERN account not allowed."), category="danger")
        return redirect("/")


def account_info_rest(remote, resp):
    """Retrieve remote account information used to find local user."""
    try:
        return _account_info(remote, resp)
    except OAuthCERNRejectedAccountError as e:
        current_app.logger.warning(e.message, exc_info=True)
        remote_app_config = current_app.config["OAUTHCLIENT_REST_REMOTE_APPS"][
            remote.name
        ]
        return response_handler(
            remote,
            remote_app_config["error_redirect_url"],
            payload=dict(message="CERN account not allowed.", code=400),
        )


@require_more_than_one_external_account
def _disconnect(remote, *args, **kwargs):
    """Handle unlinking of remote account."""
    if not current_user.is_authenticated:
        return current_app.login_manager.unauthorized()

    account = RemoteAccount.get(
        user_id=current_user.get_id(), client_id=remote.consumer_key
    )
    if account:
        external_id = account.extra_data.get("external_id")

        if external_id:
            oauth_unlink_external_id(dict(id=external_id, method="cern_openid"))

        with db.session.begin_nested():
            account.delete()

    disconnect_identity(g.identity)


def disconnect_handler(remote, *args, **kwargs):
    """Handle unlinking of remote account."""
    _disconnect(remote, *args, **kwargs)
    return redirect(url_for("invenio_oauthclient_settings.index"))


def disconnect_rest_handler(remote, *args, **kwargs):
    """Handle unlinking of remote account."""
    _disconnect(remote, *args, **kwargs)
    redirect_url = current_app.config["OAUTHCLIENT_REST_REMOTE_APPS"][remote.name][
        "disconnect_redirect_url"
    ]
    return response_handler(remote, redirect_url)


def account_setup(remote, token, resp):
    """Perform additional setup after user have been logged in."""
    resource = get_resource(remote, resp)

    with db.session.begin_nested():
        external_id = resource.get("cern_upn")

        # Set CERN person ID in extra_data.
        token.remote_account.extra_data = {"external_id": external_id}
        roles = account_roles_and_extra_data(token.remote_account, resource)
        assert not isinstance(g.identity, AnonymousIdentity)
        extend_identity(g.identity, roles)

        user = token.remote_account.user

        # Create user <-> external id link.
        oauth_link_external_id(user, dict(id=external_id, method="cern_openid"))


@identity_changed.connect
def on_identity_changed(sender, identity):
    """Store roles in session whenever identity changes.

    :param identity: The user identity where information are stored.
    """
    if isinstance(identity, AnonymousIdentity):
        disconnect_identity(identity)
        return

    # This is not ideal: it assumes that the personal token used this CERN contrib
    # method to login, which might not be the case.
    # However, it is not harmful because it will simply fetch the extra roles cached
    # in the DB.
    # Changing this requires large refactoring.
    logged_in_via_token = hasattr(current_user, "login_via_oauth2") and getattr(
        current_user, "login_via_oauth2"
    )

    remote = g.get("oauth_logged_in_with_remote", None)
    logged_in_with_cern_openid = remote and remote.name == "cern_openid"

    client_id = current_app.config["CERN_APP_OPENID_CREDENTIALS"]["consumer_key"]
    remote_account = RemoteAccount.get(
        user_id=current_user.get_id(), client_id=client_id
    )

    roles = []
    if remote_account and logged_in_via_token:
        # use cached roles, fetched from the DB
        roles.extend(remote_account.extra_data.get("roles", []))
    elif remote_account and logged_in_with_cern_openid:
        # new login, fetch roles remotely
        refresh = current_app.config.get(
            "OAUTHCLIENT_CERN_OPENID_REFRESH_TIMEDELTA",
            OAUTHCLIENT_CERN_OPENID_REFRESH_TIMEDELTA,
        )
        if refresh:
            resource = get_resource(remote)
            roles.extend(
                account_roles_and_extra_data(
                    remote_account, resource, refresh_timedelta=refresh
                )
            )
        else:
            roles.extend(remote_account.extra_data.get("roles", []))

    # must be always called, to add the user email in the roles
    extend_identity(identity, roles)


@identity_loaded.connect
def on_identity_loaded(sender, identity):
    """Store roles in session whenever identity is loaded."""
    key = current_app.config.get(
        "OAUTHCLIENT_CERN_OPENID_SESSION_KEY",
        OAUTHCLIENT_CERN_OPENID_SESSION_KEY,
    )
    identity.provides.update(session.get(key, []))
