# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Handlers for customizing oauthclient endpoints."""

from functools import partial, wraps

import six
from flask import abort, current_app, session
from flask_login import current_user
from invenio_db import db
from werkzeug.utils import import_string

from ..errors import OAuthClientError, OAuthRejectedRequestError, \
    OAuthResponseError
from ..models import RemoteAccount, RemoteToken
from ..proxies import current_oauthclient


#
# Token handling
#
def get_session_next_url(remote_app):
    """Return redirect url stored in session.

    :param remote_app: The remote application.
    :returns: The redirect URL.
    """
    return session.get(
        '%s_%s' % (token_session_key(remote_app), 'next_url')
    )


def set_session_next_url(remote_app, url):
    """Store redirect url in session for security reasons.

    :param remote_app: The remote application.
    :param url: the redirect URL.
    """
    session['%s_%s' % (token_session_key(remote_app), 'next_url')] = \
        url


def token_session_key(remote_app):
    """Generate a session key used to store the token for a remote app.

    :param remote_app: The remote application.
    :returns: The session key.
    """
    return '%s_%s' % (current_app.config['OAUTHCLIENT_SESSION_KEY_PREFIX'],
                      remote_app)


def response_token_setter(remote, resp):
    """Extract token from response and set it for the user.

    :param remote: The remote application.
    :param resp: The response.
    :raises invenio_oauthclient.errors.OAuthClientError: If authorization with
        remote service failed.
    :raises invenio_oauthclient.errors.OAuthResponseError: In case of bad
        authorized request.
    :returns: The token.
    """
    if resp is None:
        raise OAuthRejectedRequestError('User rejected request.', remote, resp)
    else:
        if 'access_token' in resp:
            return oauth2_token_setter(remote, resp)
        elif 'oauth_token' in resp and 'oauth_token_secret' in resp:
            return oauth1_token_setter(remote, resp)
        elif 'error' in resp:
            # Only OAuth2 specifies how to send error messages
            raise OAuthClientError(
                'Authorization with remote service failed.', remote, resp,
            )
    raise OAuthResponseError('Bad OAuth authorized request', remote, resp)


def oauth1_token_setter(remote, resp, token_type='', extra_data=None):
    """Set an OAuth1 token.

    :param remote: The remote application.
    :param resp: The response.
    :param token_type: The token type. (Default: ``''``)
    :param extra_data: Extra information. (Default: ``None``)
    :returns: A :class:`invenio_oauthclient.models.RemoteToken` instance.
    """
    return token_setter(
        remote,
        resp['oauth_token'],
        secret=resp['oauth_token_secret'],
        extra_data=extra_data,
        token_type=token_type,
    )


def oauth2_token_setter(remote, resp, token_type='', extra_data=None):
    """Set an OAuth2 token.

    The refresh_token can be used to obtain a new access_token after
    the old one is expired. It is saved in the database for long term use.
    A refresh_token will be present only if `access_type=offline` is included
    in the authorization code request.

    :param remote: The remote application.
    :param resp: The response.
    :param token_type: The token type. (Default: ``''``)
    :param extra_data: Extra information. (Default: ``None``)
    :returns: A :class:`invenio_oauthclient.models.RemoteToken` instance.
    """
    return token_setter(
        remote,
        resp['access_token'],
        secret='',
        token_type=token_type,
        extra_data=extra_data,
    )


def token_setter(remote, token, secret='', token_type='', extra_data=None,
                 user=None):
    """Set token for user.

    :param remote: The remote application.
    :param token: The token to set.
    :param token_type: The token type. (Default: ``''``)
    :param extra_data: Extra information. (Default: ``None``)
    :param user: The user owner of the remote token. If it's not defined,
        the current user is used automatically. (Default: ``None``)
    :returns: A :class:`invenio_oauthclient.models.RemoteToken` instance or
        ``None``.
    """
    session[token_session_key(remote.name)] = (token, secret)
    user = user or current_user

    # Save token if user is not anonymous (user exists but can be not active at
    # this moment)
    if not user.is_anonymous:
        uid = user.id
        cid = remote.consumer_key

        # Check for already existing token
        t = RemoteToken.get(uid, cid, token_type=token_type)

        if t:
            t.update_token(token, secret)
        else:
            t = RemoteToken.create(
                uid, cid, token, secret,
                token_type=token_type, extra_data=extra_data
            )
        return t
    return None


def token_getter(remote, token=''):
    """Retrieve OAuth access token.

    Used by flask-oauthlib to get the access token when making requests.

    :param remote: The remote application.
    :param token: Type of token to get. Data passed from ``oauth.request()`` to
        identify which token to retrieve. (Default: ``''``)
    :returns: The token.
    """
    session_key = token_session_key(remote.name)

    if session_key not in session and current_user.is_authenticated:
        # Fetch key from token store if user is authenticated, and the key
        # isn't already cached in the session.
        remote_token = RemoteToken.get(
            current_user.get_id(),
            remote.consumer_key,
            token_type=token,
        )

        if remote_token is None:
            return None

        # Store token and secret in session
        session[session_key] = remote_token.token()

    return session.get(session_key, None)


def token_delete(remote, token=''):
    """Remove OAuth access tokens from session.

    :param remote: The remote application.
    :param token: Type of token to get. Data passed from ``oauth.request()``
        to identify which token to retrieve. (Default: ``''``)
    :returns: The token.
    """
    session_key = token_session_key(remote.name)
    return session.pop(session_key, None)


def oauth_logout_handler(sender_app, user=None):
    """Remove all access tokens from session on logout."""
    oauth = current_oauthclient.oauth
    for remote in oauth.remote_apps.values():
        token_delete(remote)
    db.session.commit()


#
# Helpers
#
def make_handler(f, remote, with_response=True):
    """Make a handler for authorized and disconnect callbacks.

    :param f: Callable or an import path to a callable
    """
    if isinstance(f, six.string_types):
        f = import_string(f)

    @wraps(f)
    def inner(*args, **kwargs):
        if with_response:
            return f(args[0], remote, *args[1:], **kwargs)
        else:
            return f(remote, *args, **kwargs)
    return inner


def make_token_getter(remote):
    """Make a token getter for a remote application."""
    return partial(token_getter, remote)


def authorized_handler(f, authorized_response):
    """Handles an OAuth callback.

    As authorized_handler is deprecated in favor of authorized_response,
    it's has to be wrapped with handler which will be executed
    at the proper time.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        data = authorized_response()
        return f(*((data,) + args), **kwargs)
    return decorated


def require_more_than_one_external_account(f):
    """Require that the user has more than one external account for login.

    If the user only has one linked external account and no means for logging
    in via local credentials, the decorated function won't be executed.
    This decorator is useful for disconnect handlers, to prevent users from
    disconnecting their last potential means of authentication.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if current_user.is_anonymous:
            return f(*args, **kwargs)

        local_login_enabled = current_app.config.get(
            "ACCOUNTS_LOCAL_LOGIN_ENABLED", True
        )
        password_set = current_user.password is not None
        local_login_possible = local_login_enabled and password_set

        remote_apps = current_app.config["OAUTHCLIENT_REMOTE_APPS"]
        accounts = RemoteAccount.query.filter_by(
            user_id=current_user.get_id()
        ).all()

        # find out all of the linked external accounts for the user
        # that are currently configured and not hidden
        linked_accounts = [
            acc for acc in accounts
            if acc.client_id in remote_apps and
            not remote_apps[acc.client_id].get("hide", False)
        ]

        # execute the function only if local login is possible, or
        # there's more than one linked external account
        if local_login_possible or len(linked_accounts) > 1:
            return f(*args, **kwargs)

        else:
            abort(400)

    return decorated
