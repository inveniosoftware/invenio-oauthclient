# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2019 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Handlers for customizing oauthclient endpoints."""

from flask import current_app, session
from flask_login import current_user
from invenio_accounts.models import Role
from invenio_accounts.proxies import current_datastore
from invenio_db import db

from ..errors import (
    OAuthClientAlreadyAuthorized,
    OAuthClientMustRedirectLogin,
    OAuthClientMustRedirectSignup,
    OAuthClientTokenNotFound,
    OAuthClientTokenNotSet,
    OAuthClientUnAuthorized,
    OAuthClientUserNotRegistered,
)
from ..models import RemoteAccount
from ..proxies import current_oauthclient
from ..signals import (
    account_info_received,
    account_setup_committed,
    account_setup_received,
)
from ..utils import (
    create_csrf_disabled_registrationform,
    fill_form,
    oauth_authenticate,
    oauth_get_user,
    oauth_register,
)
from .utils import (
    get_session_next_url,
    require_more_than_one_external_account,
    response_token_setter,
    token_getter,
    token_session_key,
    token_setter,
)


def _role_needs_update(role_obj, new_role_dict):
    """Checks if role needs to be updated."""
    if role_obj.name != new_role_dict.get(
        "name"
    ) or role_obj.description != new_role_dict.get("description"):
        return True
    return False


def create_or_update_groups(account_groups):
    """Creates the roles based on the groups provided."""
    roles_id = []
    for group in account_groups:
        existing_role = current_datastore.find_role_by_id(group["id"])
        if existing_role and existing_role.is_managed:
            current_app.logger.exception(
                f'Error while syncing roles: A managed role with id: ${group["id"]} already exists'
            )
            continue
        existing_role_by_name = current_datastore.find_role(group["name"])
        if existing_role_by_name and existing_role_by_name.is_managed:
            current_app.logger.exception(
                f'Error while syncing roles: A managed role with name: ${group["name"]} already exists'
            )
            continue
        if not existing_role:
            role = current_datastore.create_role(
                id=group["id"],
                name=group.get("name"),
                description=group.get("description"),
                is_managed=False,
            )
            roles_id.append(role.id)
        elif existing_role and _role_needs_update(existing_role, group):
            role_to_update = Role(
                id=group["id"],
                name=group.get("name"),
                description=group.get("description"),
                is_managed=False,
            )
            role = current_datastore.update_role(role_to_update)
            roles_id.append(role.id)
        else:
            roles_id.append(existing_role.id)

    current_datastore.commit()

    return roles_id


#
# Handlers
#
def base_authorized_signup_handler(resp, remote, *args, **kwargs):
    """Handle sign-in/up functionality.

    :param remote: The remote application.
    :param resp: The response of the `authorized` endpoint.
    :returns: Redirect response.
    """
    # Remove any previously stored auto register session key
    session.pop(token_session_key(remote.name) + "_autoregister", None)
    # We set the remote in the session to be aware of which one is being used and, on log out redirect to
    # the correct URL set in the OAUTHCLIENT_REMOTE_APPS for each remote
    session["OAUTHCLIENT_SESSION_REMOTE_NAME"] = remote.name
    # Store token in session
    # ----------------------
    # Set token in session - token object only returned if
    # current_user.is_authenticated().
    token = response_token_setter(remote, resp)
    handlers = current_oauthclient.signup_handlers[remote.name]
    # Needed for tests
    if not current_user.is_authenticated:
        # Sign-in/up user
        # ---------------
        account_info = handlers["info"](resp)
        assert "external_id" in account_info
        account_info_received.send(
            remote, token=token, response=resp, account_info=account_info
        )

        user = oauth_get_user(
            remote.consumer_key,
            account_info=account_info,
            access_token=token_getter(remote)[0],
        )

        if user is None:
            # Auto sign-up if user not found
            form = create_csrf_disabled_registrationform(remote)
            form = fill_form(form, account_info["user"])
            remote_app = current_app.config["OAUTHCLIENT_REMOTE_APPS"][remote.name]
            precedence_mask = remote_app.get("precedence_mask")
            signup_options = remote_app.get("signup_options")
            user = oauth_register(
                form,
                account_info["user"],
                precedence_mask=precedence_mask,
                signup_options=signup_options,
            )

            # if registration fails ...
            if user is None:
                # requires extra information
                session[token_session_key(remote.name) + "_autoregister"] = True
                session[token_session_key(remote.name) + "_account_info"] = account_info
                session[token_session_key(remote.name) + "_response"] = resp
                db.session.commit()
                raise OAuthClientMustRedirectSignup()

        group_handler = handlers.get("groups")
        if group_handler:
            account_groups = group_handler(resp)
            if account_groups:
                roles_id = create_or_update_groups(account_groups)
                # We set the unmanaged groups in the session because they are not linked to the user in the DB
                session["_unmanaged_groups"] = roles_id

        # Authenticate user after the unmanaged groups where set in the session
        if not oauth_authenticate(
            remote.consumer_key, user, require_existing_link=False
        ):
            raise OAuthClientUnAuthorized()

        # Link account
        # ------------
        # Need to store token in database instead of only the session when
        # called first time.
        token = response_token_setter(remote, resp)

    # Setup account
    # -------------
    if not token.remote_account.extra_data:
        account_setup = handlers["setup"](token, resp)
        account_setup_received.send(
            remote, token=token, response=resp, account_setup=account_setup
        )
        db.session.commit()
        account_setup_committed.send(remote, token=token)
    else:
        db.session.commit()

    # Redirect to next
    next_url = get_session_next_url(remote.name)
    if next_url:
        return next_url


@require_more_than_one_external_account
def base_disconnect_handler(remote, *args, **kwargs):
    """Handle unlinking of remote account.

    This default handler will just delete the remote account link. You may
    wish to extend this module to perform clean-up in the remote service
    before removing the link (e.g. removing install webhooks).

    :param remote: The remote application.
    :returns: Redirect response.
    """
    if not current_user.is_authenticated:
        raise OAuthClientUnAuthorized()

    with db.session.begin_nested():
        account = RemoteAccount.get(
            user_id=current_user.get_id(), client_id=remote.consumer_key
        )
        if account:
            account.delete()

    db.session.commit()


def base_signup_handler(remote, form, *args, **kwargs):
    """Handle extra signup information.

    :param remote: The remote application.
    :returns: Redirect response or the template rendered.
    """
    # User already authenticated so move on
    if current_user.is_authenticated:
        raise OAuthClientAlreadyAuthorized()

    # Retrieve token from session
    oauth_token = token_getter(remote)
    if not oauth_token:
        raise OAuthClientTokenNotFound()

    session_prefix = token_session_key(remote.name)

    # Test to see if this is coming from on authorized request
    if not session.get(session_prefix + "_autoregister", False):
        raise OAuthClientMustRedirectLogin()

    if form.validate_on_submit():
        account_info = session.get(session_prefix + "_account_info")
        response = session.get(session_prefix + "_response")

        remote_app = current_app.config["OAUTHCLIENT_REMOTE_APPS"][remote.name]
        precedence_mask = remote_app.get("precedence_mask")
        signup_options = remote_app.get("signup_options")

        # Register user
        user = oauth_register(
            form,
            account_info["user"],
            precedence_mask=precedence_mask,
            signup_options=signup_options,
        )

        if user is None:
            raise OAuthClientUserNotRegistered()

        # Remove session key
        session.pop(session_prefix + "_autoregister", None)

        # Link account and set session data
        token = token_setter(remote, oauth_token[0], secret=oauth_token[1], user=user)
        handlers = current_oauthclient.signup_handlers[remote.name]

        if token is None:
            raise OAuthClientTokenNotSet()

        if not token.remote_account.extra_data:
            account_setup = handlers["setup"](token, response)
            account_setup_received.send(
                remote, token=token, response=response, account_setup=account_setup
            )
            # Registration has been finished
            db.session.commit()
            account_setup_committed.send(remote, token=token)
        else:
            # Registration has been finished
            db.session.commit()

        # Authenticate user
        if not oauth_authenticate(
            remote.consumer_key, user, require_existing_link=False
        ):
            raise OAuthClientUnAuthorized()

        # Remove account info from session
        session.pop(session_prefix + "_account_info", None)
        session.pop(session_prefix + "_response", None)

        # Redirect to next
        next_url = get_session_next_url(remote.name)
        if next_url:
            return next_url

    # Pre-fill form
    account_info = session.get(session_prefix + "_account_info")
    if not form.is_submitted():
        fill_form(form, account_info["user"])
