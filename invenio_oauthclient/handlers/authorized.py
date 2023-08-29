# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2023 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Authorize handlers."""

from flask import current_app, session
from flask_login import current_user
from flask_security.confirmable import requires_confirmation
from flask_security.utils import get_message
from invenio_db import db

from ..errors import (
    OAuthClientAlreadyAuthorized,
    OAuthClientMustRedirectSignup,
    OAuthClientTokenNotFound,
    OAuthClientTokenNotSet,
    OAuthClientUnAuthorized,
    OAuthClientUserNotRegistered,
    OAuthClientUserRequiresConfirmation,
)
from ..oauth import oauth_authenticate, oauth_get_user, oauth_register
from ..proxies import current_oauthclient
from ..signals import (
    account_info_received,
    account_setup_committed,
    account_setup_received,
)
from ..tasks import create_or_update_roles_task
from ..utils import create_csrf_disabled_registrationform, fill_form
from .token import (
    get_session_next_url,
    response_token_setter,
    token_getter,
    token_session_key,
    token_setter,
)


def authorized_handler(resp, remote, *args, **kwargs):
    """Handle user login after OAuth authorize step.

    :param resp: The response of the `authorized` endpoint.
    :param remote: The remote application.
    :returns: The URL to go next after login
    """
    # Validate the response and set token in the user session. This must happen
    # first to make sure that the response payload is valid.
    # Returned token is None when anonymous user
    token = response_token_setter(remote, resp)

    # Set the remote in the user session to know how the user logged in.
    # Useful on log out, so that we can logout on remote too, when needed.
    session["OAUTHCLIENT_SESSION_REMOTE_NAME"] = remote.name
    # Remove any previously stored auto register session key
    session.pop(token_session_key(remote.name) + "_autoregister", None)

    handlers = current_oauthclient.signup_handlers[remote.name]

    # call user info endpoint
    account_info = handlers["info"](resp)
    assert "external_id" in account_info
    account_info_received.send(remote, response=resp, account_info=account_info)

    # call groups endpoint, when defined
    session["unmanaged_roles_ids"] = set()
    groups_handler = handlers.get("groups")
    if groups_handler:
        groups = groups_handler(resp)
        if groups:
            # preventively add/update Invenio roles based on the fetched user groups
            # (async), so that new groups are almost immediately searchable
            create_or_update_roles_task.delay(groups)
            # Set the unmanaged roles in the user session, used in other modules.
            # Unmanaged user roles are not stored in the DB for privacy reasons:
            # sys admins should not know the external groups of a user.
            session["unmanaged_roles_ids"] = set(group["id"] for group in groups)

    # In the normal OAuth flow, the user is not yet authenticated. However, it the user
    # is already logged in, and goes to 'Linked accounts', clicks 'Connect' on another
    # remote app, `authorized` will be called with the new remote.
    is_normal_oauth_flow = not current_user.is_authenticated
    if is_normal_oauth_flow:
        # get the user from the DB using the current remote
        user = oauth_get_user(
            remote.consumer_key,
            account_info=account_info,
            access_token=token_getter(remote)[0],
        )
        if user is None:
            # User not found, this is the first login. Register the user.
            # The registration raises an exception when the account info is not enough
            # to register the user.
            form = create_csrf_disabled_registrationform(remote)
            form = fill_form(form, account_info["user"])

            try:
                user = _register_user(resp, remote, account_info, form)
            except OAuthClientUserNotRegistered:
                # save in the session info to display the extra signup form to the user
                session[token_session_key(remote.name) + "_autoregister"] = True
                session[token_session_key(remote.name) + "_account_info"] = account_info
                session[token_session_key(remote.name) + "_response"] = resp
                db.session.commit()
                # this will trigger a redirect to /signup (therefor
                # signup_handler/extra_signup_handler funcs) and will require the user
                # to fill in the registration form with the missing information
                raise OAuthClientMustRedirectSignup()

        # check if user requires confirmation
        # that happens when user was previously logged in but email was not yet
        # confirmed
        if requires_confirmation(user):
            raise OAuthClientUserRequiresConfirmation(user=user)

        if not oauth_authenticate(
            remote.consumer_key,
            user,
            require_existing_link=False,
            require_user_confirmation=False,
        ):
            raise OAuthClientUnAuthorized()

        # Store token in the database instead of only the session
        token = response_token_setter(remote, resp)

    _complete_authorize(resp, remote, handlers, token)

    # Return the URL where to go next
    next_url = get_session_next_url(remote.name)
    if next_url:
        return next_url


def _register_user(resp, remote, account_info, form):
    """Try to register the user with info got from the remote app.

    :param resp: The response of the `authorized` endpoint.
    :param remote: The remote application.
    """
    remote_app = current_app.config["OAUTHCLIENT_REMOTE_APPS"][remote.name]
    precedence_mask = remote_app.get("precedence_mask")
    signup_options = remote_app.get("signup_options")

    user = oauth_register(
        form,
        account_info["user"],
        precedence_mask=precedence_mask,
        signup_options=signup_options,
    )

    if user is None:
        # Registration failed: the account info is not enough to register the user.
        # Save info in the session, necessary for the user registration flow with form.
        raise OAuthClientUserNotRegistered()

    return user


def _complete_authorize(resp, remote, handlers, token):
    """Complete authorized flow.

    This happens after:
     - A normal authorized flow.
     - The extra signup registration, where the user needs to fill in the missing
       information during the first login.
    """
    is_first_login_with_this_remote = not token.remote_account.extra_data
    if is_first_login_with_this_remote:
        # call the `setup` handler to get complete the first login with this remote
        account_setup = handlers["setup"](token, resp)
        account_setup_received.send(
            remote, token=token, response=resp, account_setup=account_setup
        )
        db.session.commit()
        account_setup_committed.send(remote, token=token)
    else:
        db.session.commit()


def extra_signup_handler(remote, form, *args, **kwargs):
    """Handle extra signup information.

    Validate the extra missing information that the user inserted in the signup step,
    after authorized. If the info inserted are enough

    :param remote: The remote application.
    :returns: Redirect response or the template rendered.
    """
    if current_user.is_authenticated:
        raise OAuthClientAlreadyAuthorized()

    # Retrieve token from session
    oauth_token = token_getter(remote)
    if not oauth_token:
        raise OAuthClientTokenNotFound()

    session_prefix = token_session_key(remote.name)

    handlers = current_oauthclient.signup_handlers[remote.name]
    if form.validate_on_submit():
        # remove the autoregister flag that marks the authorized flow
        session.pop(session_prefix + "_autoregister", None)
        account_info = session.pop(session_prefix + "_account_info")
        response = session.pop(session_prefix + "_response")

        user = _register_user(response, remote, account_info, form)

        # Link account and set session data
        token = token_setter(remote, oauth_token[0], secret=oauth_token[1], user=user)
        if token is None:
            raise OAuthClientTokenNotSet()

        # check if user requires confirmation
        # that happens when user was previously logged in but email was not yet
        # confirmed
        if requires_confirmation(user):
            _complete_authorize(response, remote, handlers, token)
            raise OAuthClientUserRequiresConfirmation(user=user)

        # Authenticate user, without requiring the existence of the RemoteAccount,
        # which is created later in the setup handler.
        if not oauth_authenticate(
            remote.consumer_key,
            user,
            require_existing_link=False,
            require_user_confirmation=False,
        ):
            raise OAuthClientUnAuthorized()

        _complete_authorize(response, remote, handlers, token)
        # Return the URL where to go next
        next_url = get_session_next_url(remote.name)
        if next_url:
            return next_url
