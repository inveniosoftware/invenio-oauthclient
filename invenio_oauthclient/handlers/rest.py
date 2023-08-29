# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2022 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Handlers for customizing oauthclient endpoints."""

from functools import partial, wraps
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

from flask import (
    abort,
    current_app,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user
from invenio_db import db

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
    OAuthClientUserRequiresConfirmation,
    OAuthError,
    OAuthRejectedRequestError,
)
from ..proxies import current_oauthclient
from ..utils import create_csrf_disabled_registrationform, fill_form
from .authorized import authorized_handler, extra_signup_handler
from .base import base_disconnect_handler
from .decorators import can_extra_signup
from .token import response_token_setter


def response_handler_postmessage(remote, url, payload=None):
    """Postmessage response handler."""
    return render_template("invenio_oauthclient/postmessage.html", payload=payload)


def default_response_handler(url, payload=None):
    """Default response handler."""
    scheme, netloc, path, query, fragment = urlsplit(url)
    qs = parse_qs(query)
    if payload:
        qs.update(payload)
    query = urlencode(qs)
    url = urlunsplit((scheme, netloc, path, query, fragment))
    return redirect(url)


def default_remote_response_handler(remote, url, payload=None):
    """Default response handler."""
    return default_response_handler(url, payload=payload)


def response_handler(remote, url, payload=None):
    """Handle oauthclient rest response."""
    if not remote:
        return current_oauthclient.default_response_handler(url, payload)
    return current_oauthclient.remote_app_response_handler[remote.name](
        remote, url, payload
    )


def _oauth_error_handler(remote, f, *args, **kwargs):
    """Function to handle exceptions."""
    remote_app_config = current_app.config["OAUTHCLIENT_REST_REMOTE_APPS"][remote.name]
    try:
        return f(remote, *args, **kwargs)
    except OAuthClientError as e:
        current_app.logger.warning(e.message, exc_info=True)
        return response_handler(
            remote,
            remote_app_config["error_redirect_url"],
            payload=dict(message="Authorization with remote service failed.", code=400),
        )
    except OAuthRejectedRequestError:
        return response_handler(
            remote,
            remote_app_config["error_redirect_url"],
            payload=dict(message="You rejected the authentication request.", code=400),
        )
    except AlreadyLinkedError:
        msg = "External service is already linked to another account."
        return response_handler(
            remote,
            remote_app_config["error_redirect_url"],
            payload=dict(message=msg, code=400),
        )
    except (OAuthClientUnAuthorized, OAuthClientUserRequiresConfirmation):
        return response_handler(
            remote,
            remote_app_config["error_redirect_url"],
            payload=dict(message="Unauthorized.", code=401),
        )
    except OAuthClientAlreadyAuthorized:
        return response_handler(
            remote,
            remote_app_config["authorized_redirect_url"],
            payload=dict(
                message="Successfully signed up.",
                code=200,
            ),
        )
    except OAuthClientTokenNotFound:
        return response_handler(
            remote,
            remote_app_config["error_redirect_url"],
            payload=dict(
                message="Token not found.",
                code=400,
            ),
        )
    except OAuthClientUserNotRegistered:
        abort(make_response(jsonify(message="Form validation error."), 400))
    except OAuthClientTokenNotSet:
        raise OAuthError("Could not create token for user.", remote)
    except OAuthClientMustRedirectSignup as e:
        return redirect(
            url_for(
                ".rest_signup",
                remote_app=remote.name,
            )
        )
    except OAuthClientMustRedirectLogin as e:
        return redirect(
            url_for(
                ".rest_login",
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
    remote_app_config = current_app.config["OAUTHCLIENT_REST_REMOTE_APPS"][remote.name]

    response_token_setter(remote, resp)
    db.session.commit()
    return response_handler(
        remote,
        remote_app_config["authorized_redirect_url"],
    )


@oauth_resp_remote_error_handler
def authorized_signup_handler(resp, remote, *args, **kwargs):
    """Handle sign-in/up functionality.

    :param remote: The remote application.
    :param resp: The response.
    :returns: Redirect response.
    """
    remote_app_config = current_app.config["OAUTHCLIENT_REST_REMOTE_APPS"][remote.name]
    next_url = authorized_handler(resp, remote, *args, **kwargs)
    response_payload = dict(message="Successfully authorized.", code=200)
    if next_url:
        response_payload["next_url"] = next_url

    return response_handler(
        remote, remote_app_config["authorized_redirect_url"], payload=response_payload
    )


@oauth_remote_error_handler
def disconnect_handler(remote, *args, **kwargs):
    """Handle unlinking of remote account.

    This default handler will just delete the remote account link. You may
    wish to extend this module to perform clean-up in the remote service
    before removing the link (e.g. removing install webhooks).

    :param remote: The remote application.
    :returns: Redirect response.
    """
    remote_app_config = current_app.config["OAUTHCLIENT_REST_REMOTE_APPS"][remote.name]
    base_disconnect_handler(remote, *args, **kwargs)
    redirect_url = current_app.config["OAUTHCLIENT_REST_REMOTE_APPS"][remote.name][
        "disconnect_redirect_url"
    ]

    return response_handler(
        remote,
        redirect_url,
        payload=dict(
            message="Successfully disconnected.",
            code=200,
        ),
    )


@oauth_remote_error_handler
@can_extra_signup
def signup_handler(remote, *args, **kwargs):
    """Handle extra signup information.

    This should be called when the account info from the remote `info` endpoint is
    not enough to register the user (e.g. e-mail missing): it will show the
    registration form, validate it on submission and register the user.

    :param remote: The remote application.
    :returns: Redirect response or the template rendered.
    """
    remote_app_config = current_app.config["OAUTHCLIENT_REST_REMOTE_APPS"][remote.name]
    form = create_csrf_disabled_registrationform(remote)
    if not form.is_submitted():
        # Show the form when the user is redirected here after `authorized`
        # (GET request), to fill in the missing information (e.g. e-mail)
        data = request.form.to_dict()
        form = fill_form(form, data)
        return response_handler(
            remote,
            remote_app_config["signup_redirect_url"],
            payload=dict(
                form=form.to_dict(),
                remote=remote.name,
                app_title=remote_app_config.get("title", ""),
                app_description=remote_app_config.get("description", ""),
                app_icon=remote_app_config.get("icon", None),
            ),
        )
    elif form.is_submitted():
        # Form is submitted (POST request): validate the user input and register
        # the user
        try:
            next_url = extra_signup_handler(remote, form, *args, **kwargs)
        except OAuthClientUnAuthorized:
            abort(401)

        response_payload = dict(message="Successfully signed up.", code=200)
        if next_url:
            response_payload["next_url"] = next_url
        return jsonify(response_payload)
