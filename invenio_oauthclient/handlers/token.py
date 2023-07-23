# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2023 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Funcs to manage tokens."""

from functools import partial

from flask import current_app, session
from flask_login import current_user
from invenio_db import db

from ..errors import OAuthClientError, OAuthRejectedRequestError, OAuthResponseError
from ..models import RemoteToken
from ..proxies import current_oauthclient


def get_session_next_url(remote_app):
    """Return redirect url stored in session.

    :param remote_app: The remote application.
    :returns: The redirect URL.
    """
    return session.get("%s_%s" % (token_session_key(remote_app), "next_url"))


def set_session_next_url(remote_app, url):
    """Store redirect url in session for security reasons.

    :param remote_app: The remote application.
    :param url: the redirect URL.
    """
    session["%s_%s" % (token_session_key(remote_app), "next_url")] = url


def token_session_key(remote_app):
    """Generate a session key used to store the token for a remote app.

    :param remote_app: The remote application.
    :returns: The session key.
    """
    return "%s_%s" % (current_app.config["OAUTHCLIENT_SESSION_KEY_PREFIX"], remote_app)


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
        raise OAuthRejectedRequestError("User rejected request.", remote, resp)
    else:
        if "access_token" in resp:
            return oauth2_token_setter(remote, resp)
        elif "oauth_token" in resp and "oauth_token_secret" in resp:
            return oauth1_token_setter(remote, resp)
        elif "error" in resp:
            # Only OAuth2 specifies how to send error messages
            raise OAuthClientError(
                "Authorization with remote service failed.",
                remote,
                resp,
            )
    raise OAuthResponseError("Bad OAuth authorized request", remote, resp)


def oauth1_token_setter(remote, resp, token_type="", extra_data=None):
    """Set an OAuth1 token.

    :param remote: The remote application.
    :param resp: The response.
    :param token_type: The token type. (Default: ``''``)
    :param extra_data: Extra information. (Default: ``None``)
    :returns: A :class:`invenio_oauthclient.models.RemoteToken` instance.
    """
    return token_setter(
        remote,
        resp["oauth_token"],
        secret=resp["oauth_token_secret"],
        extra_data=extra_data,
        token_type=token_type,
    )


def oauth2_token_setter(remote, resp, token_type="", extra_data=None):
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
        resp["access_token"],
        secret="",
        token_type=token_type,
        extra_data=extra_data,
    )


def token_setter(remote, token, secret="", token_type="", extra_data=None, user=None):
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
                uid, cid, token, secret, token_type=token_type, extra_data=extra_data
            )
        return t
    return None


def token_getter(remote, token=""):
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


def token_delete(remote, token=""):
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


def make_token_getter(remote):
    """Make a token getter for a remote application."""
    return partial(token_getter, remote)
