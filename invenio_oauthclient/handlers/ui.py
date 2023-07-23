# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2019 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Handlers for customizing oauthclient endpoints."""

from functools import partial, wraps

from flask import (
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user
from invenio_db import db
from invenio_i18n import gettext as _

from ..errors import (
    AlreadyLinkedError,
    OAuthClientAlreadyAuthorized,
    OAuthClientError,
    OAuthClientMustRedirectLogin,
    OAuthClientMustRedirectSignup,
    OAuthClientTokenNotFound,
    OAuthClientTokenNotSet,
    OAuthClientUnAuthorized,
    OAuthClientUserNotRegistered,
    OAuthError,
    OAuthRejectedRequestError,
)
from ..utils import create_registrationform, fill_form
from .authorized import authorized_handler, extra_signup_handler
from .base import base_disconnect_handler
from .decorators import can_extra_signup
from .token import response_token_setter, token_session_key


def _oauth_error_handler(remote, f, *args, **kwargs):
    """Function to handle exceptions."""
    try:
        return f(remote, *args, **kwargs)
    except OAuthClientError as e:
        current_app.logger.warning(e.message, exc_info=True)
        return oauth2_handle_error(e.remote, e.response, e.code, e.uri, e.description)
    except OAuthClientUnAuthorized:
        return current_app.login_manager.unauthorized()
    except AlreadyLinkedError:
        flash(
            _("External service is already linked to another account."),
            category="danger",
        )
        return redirect(url_for("invenio_oauthclient_settings.index"))
    except OAuthRejectedRequestError:
        flash(_("You rejected the authentication request."), category="info")
        return redirect("/")
    except OAuthClientAlreadyAuthorized:
        return redirect("/")
    except OAuthClientTokenNotFound:
        return redirect("/")
    except OAuthClientUserNotRegistered:
        raise OAuthError("Could not create user.", remote)
    except OAuthClientTokenNotSet:
        raise OAuthError("Could not create token for user.", remote)
    except OAuthClientMustRedirectSignup as e:
        return redirect(
            url_for(
                ".signup",
                remote_app=remote.name,
            )
        )
    except OAuthClientMustRedirectLogin as e:
        return redirect(
            url_for(
                ".login",
                remote_app=remote.name,
            )
        )


#
# Error handling decorators
#
def oauth_resp_remote_error_handler(f):
    """Decorator to handle exceptions."""

    @wraps(f)
    def inner(resp, remote, *args, **kwargs):
        # OAuthErrors should not happen, so they are not caught here. Hence
        # they will result in a 500 Internal Server Error which is what we
        # are interested in.
        _f = partial(f, resp)
        return _oauth_error_handler(remote, _f, *args, **kwargs)

    return inner


def oauth_remote_error_handler(f):
    """Decorator to handle exceptions."""

    @wraps(f)
    def inner(remote, *args, **kwargs):
        # OAuthErrors should not happen, so they are not caught here. Hence
        # they will result in a 500 Internal Server Error which is what we
        # are interested in.
        return _oauth_error_handler(remote, f, *args, **kwargs)

    return inner


#
# Handlers
#
@oauth_resp_remote_error_handler
def authorized_default_handler(resp, remote, *args, **kwargs):
    """Store access token in session.

    Default authorized handler.

    :param remote: The remote application.
    :param resp: The response.
    :returns: Redirect response.
    """
    response_token_setter(remote, resp)
    db.session.commit()
    return redirect(url_for("invenio_oauthclient_settings.index"))


@oauth_resp_remote_error_handler
def authorized_signup_handler(resp, remote, *args, **kwargs):
    """Handle sign-in/up functionality.

    :param remote: The remote application.
    :param resp: The response.
    :returns: Redirect response.
    """
    next_url = authorized_handler(resp, remote, *args, **kwargs)
    # Redirect to next
    if next_url:
        return redirect(next_url)
    return redirect(url_for("invenio_oauthclient_settings.index"))


@oauth_remote_error_handler
def disconnect_handler(remote, *args, **kwargs):
    """Handle unlinking of remote account.

    This default handler will just delete the remote account link. You may
    wish to extend this module to perform clean-up in the remote service
    before removing the link (e.g. removing install webhooks).

    :param remote: The remote application.
    :returns: Redirect response.
    """
    base_disconnect_handler(remote, *args, **kwargs)
    return redirect(url_for("invenio_oauthclient_settings.index"))


@oauth_remote_error_handler
@can_extra_signup
def signup_handler(remote, *args, **kwargs):
    """Handle extra signup information.

    The info in the request.form is used to fill in the user registration form.
    When the form does not validate (e.g. missing user e-mail), it is displayed
    to the user, who needs to fill in the missing info and submit it.
    This method is also called when the user has filled in the form and click on
    btn submit.

    :param remote: The remote application.
    :returns: Redirect response or the template rendered.
    """
    form = create_registrationform(request.form, oauth_remote_app=remote)
    if not form.is_submitted():
        session_prefix = token_session_key(remote.name)
        account_info = session.get(session_prefix + "_account_info")
        # Pre-fill form
        fill_form(form, account_info["user"])
        return render_template(
            current_app.config["OAUTHCLIENT_SIGNUP_TEMPLATE"],
            form=form,
            remote=remote,
            app_title=current_app.config["OAUTHCLIENT_REMOTE_APPS"][remote.name].get(
                "title", ""
            ),
            app_description=current_app.config["OAUTHCLIENT_REMOTE_APPS"][
                remote.name
            ].get("description", ""),
            app_icon=current_app.config["OAUTHCLIENT_REMOTE_APPS"][remote.name].get(
                "icon", None
            ),
        )
    elif not form.errors:
        try:
            next_url = extra_signup_handler(remote, form, *args, **kwargs)
        except OAuthClientUnAuthorized:
            # Redirect the user after registration (which doesn't include the
            # activation), waiting for user to confirm his email.
            return redirect(url_for("security.login"))

        if next_url:
            return redirect(next_url)
        else:
            return redirect("/")


def oauth2_handle_error(remote, resp, error_code, error_uri, error_description):
    """Handle errors during exchange of one-time code for an access tokens."""
    flash(_("Authorization with remote service failed."))
    return redirect("/")
