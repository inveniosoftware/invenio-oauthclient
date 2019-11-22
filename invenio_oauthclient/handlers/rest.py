# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Handlers for customizing oauthclient endpoints."""

from __future__ import absolute_import, print_function

from functools import partial, wraps

import six
from flask import current_app, flash, jsonify, redirect, render_template, \
    request, session, url_for
from flask_babelex import gettext as _
from flask_login import current_user
from invenio_db import db
from six.moves.urllib_parse import urlencode
from werkzeug.utils import import_string

from ..errors import AlreadyLinkedError, OAuthCERNRejectedAccountError, \
    OAuthClientError, OAuthError, OAuthRejectedRequestError, \
    OAuthResponseError
from ..models import RemoteAccount, RemoteToken
from ..proxies import current_oauthclient
from ..signals import account_info_received, account_setup_committed, \
    account_setup_received
from ..utils import create_csrf_disabled_registrationform, \
    create_registrationform, fill_form, oauth_authenticate, oauth_get_user, \
    oauth_register, rest_oauth_register
from .utils import get_session_next_url, response_token_setter, token_getter, \
    token_session_key, token_setter


def response_handler_postmessage(remote, url, payload=dict()):
    """Postmessage response handler."""
    return render_template(
        'invenio_oauthclient/postmessage.html',
        payload=payload
    )


def default_response_handler(remote, url, payload=dict()):
    """Default response handler."""
    if payload:
        return redirect(
            "{url}?{payload}".format(url=url, payload=urlencode(payload)))
    return redirect(url)


def response_handler(remote, url, payload=dict()):
    """Handle oauthclient rest response."""
    return current_oauthclient.response_handler[remote.name](
        url, payload)


#
# Error handling decorators
#
def oauth_error_handler(f):
    """Decorator to handle exceptions."""
    @wraps(f)
    def inner(resp, remote, *args, **kwargs):
        # OAuthErrors should not happen, so they are not caught here. Hence
        # they will result in a 500 Internal Server Error which is what we
        # are interested in.
        remote_app_config = current_app.config['OAUTHCLIENT_REST_REMOTE_APPS'][
            remote.name]
        try:
            return f(resp, remote, *args, **kwargs)
        except OAuthClientError as e:
            current_app.logger.warning(e.message, exc_info=True)
            return oauth2_handle_error(
                e.remote, e.response, e.code, e.uri, e.description
            )
        except OAuthCERNRejectedAccountError as e:
            current_app.logger.warning(e.message, exc_info=True)
            return response_handler(
                remote,
                remote_app_config['error_redirect_url'],
                payload=dict(
                    message='CERN account not allowed.',
                    code=400)
                )
        except OAuthRejectedRequestError:
            return response_handler(
                remote,
                remote_app_config['error_redirect_url'],
                payload=dict(
                    message='You rejected the authentication request.',
                    code=400)
                )
        except AlreadyLinkedError:
            msg = 'External service is already linked to another account.'
            return response_handler(
                remote,
                remote_app_config['error_redirect_url'],
                payload=dict(
                    message=msg,
                    code=400)
                )
    return inner


#
# Handlers
#
@oauth_error_handler
def authorized_default_handler(resp, remote, *args, **kwargs):
    """Store access token in session.

    Default authorized handler.

    :param remote: The remote application.
    :param resp: The response.
    :returns: Redirect response.
    """
    remote_app_config = current_app.config['OAUTHCLIENT_REST_REMOTE_APPS'][
        remote.name]

    response_token_setter(remote, resp)
    db.session.commit()
    return response_handler(
        remote,
        remote_app_config['authorized_redirect_url'],
        payload=dict()
    )


@oauth_error_handler
def authorized_signup_handler(resp, remote, *args, **kwargs):
    """Handle sign-in/up functionality.

    :param remote: The remote application.
    :param resp: The response.
    :returns: Redirect response.
    """
    remote_app_config = current_app.config['OAUTHCLIENT_REST_REMOTE_APPS'][
        remote.name]

    # Remove any previously stored auto register session key
    session.pop(token_session_key(remote.name) + '_autoregister', None)

    # Store token in session
    # ----------------------
    # Set token in session - token object only returned if
    # current_user.is_autenticated().
    token = response_token_setter(remote, resp)
    handlers = current_oauthclient.signup_handlers[remote.name]

    # Sign-in/up user
    # ---------------

    if not current_user.is_authenticated:
        account_info = handlers['info'](resp)
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
            current_app.logger.error(account_info['user'])
            user = rest_oauth_register(account_info['user'])
            # if registration fails ...
            if user is None:
                # requires extra information
                session[
                    token_session_key(remote.name) + '_autoregister'] = True
                session[token_session_key(remote.name) +
                        '_account_info'] = account_info
                session[token_session_key(remote.name) +
                        '_response'] = resp
                db.session.commit()
                return redirect(url_for(
                    '.signup',
                    remote_app=remote.name,
                ))

        # Authenticate user
        if not oauth_authenticate(remote.consumer_key, user,
                                  require_existing_link=False):
            return response_handler(
                remote,
                remote_app_config['error_redirect_url'],
                payload=dict(
                    message="Unauthorized.",
                    code=401
                ))

        # Link account
        # ------------
        # Need to store token in database instead of only the session when
        # called first time.
        token = response_token_setter(remote, resp)

    # Setup account
    # -------------
    if not token.remote_account.extra_data:
        account_setup = handlers['setup'](token, resp)
        account_setup_received.send(
            remote, token=token, response=resp, account_setup=account_setup
        )
        db.session.commit()
        account_setup_committed.send(remote, token=token)
    else:
        db.session.commit()

    response_payload = dict(message="Successfully authorized.", code=200)

    next_url = get_session_next_url(remote.name)
    if next_url:
        response_payload["next_url"] = next_url

    return response_handler(
        remote,
        remote_app_config['authorized_redirect_url'],
        payload=response_payload
    )


def disconnect_handler(remote, *args, **kwargs):
    """Handle unlinking of remote account.

    This default handler will just delete the remote account link. You may
    wish to extend this module to perform clean-up in the remote service
    before removing the link (e.g. removing install webhooks).

    :param remote: The remote application.
    :returns: Redirect response.
    """
    remote_app_config = current_app.config['OAUTHCLIENT_REST_REMOTE_APPS'][
        remote.name]
    if not current_user.is_authenticated:
        return response_handler(
            remote,
            remote_app_config['error_redirect_url'],
            payload=dict(
                message="Unauthorized.",
                code=401
            )
        )

    with db.session.begin_nested():
        account = RemoteAccount.get(
            user_id=current_user.get_id(),
            client_id=remote.consumer_key
        )
        if account:
            account.delete()

    db.session.commit()

    redirect_url = current_app.config['OAUTHCLIENT_REST_REMOTE_APPS'][
        remote.name]['disconnect_redirect_url']

    return response_handler(
        remote,
        redirect_url,
        payload=dict(
            message="Successfully disconnected.",
            code=200,
        )
    )


def signup_handler(remote, *args, **kwargs):
    """Handle extra signup information.

    :param remote: The remote application.
    :returns: Redirect response or the template rendered.
    """
    remote_app_config = current_app.config['OAUTHCLIENT_REST_REMOTE_APPS'][
        remote.name]
    # User already authenticated so move on
    if current_user.is_authenticated:
        return response_handler(
            remote,
            remote_app_config['authorized_redirect_url'],
            payload=dict(
                message="Successfully signed up.",
                code=200,
            )
        )

    # Retrieve token from session
    oauth_token = token_getter(remote)
    if not oauth_token:
        return response_handler(
            remote,
            remote_app_config['error_redirect_url'],
            payload=dict(
                message="Token not found.",
                code=400,
            )
        )

    session_prefix = token_session_key(remote.name)
    # Test to see if this is coming from on authorized request
    if not session.get(session_prefix + '_autoregister', False):
        return redirect(url_for('.login', remote_app=remote.name))

    if request.method == 'POST':
        account_info = session.get(session_prefix + '_account_info')
        response = session.get(session_prefix + '_response')

        # Register user
        user = rest_oauth_register(request.json)

        if user is None:
            raise OAuthError('Could not create user.', remote)

        # Remove session key
        session.pop(session_prefix + '_autoregister', None)

        # Link account and set session data
        token = token_setter(remote, oauth_token[0], secret=oauth_token[1],
                             user=user)
        handlers = current_oauthclient.signup_handlers[remote.name]

        if token is None:
            raise OAuthError('Could not create token for user.', remote)

        if not token.remote_account.extra_data:
            account_setup = handlers['setup'](token, response)
            account_setup_received.send(
                remote, token=token, response=response,
                account_setup=account_setup
            )
            # Registration has been finished
            db.session.commit()
            account_setup_committed.send(remote, token=token)
        else:
            # Registration has been finished
            db.session.commit()

        # Authenticate the user
        if not oauth_authenticate(remote.consumer_key, user,
                                  require_existing_link=False):
            return response_handler(
                remote,
                remote_app_config['error_redirect_url'],
                payload=dict(
                    message="Unauthorized.",
                    code=401
                ))

        # Remove account info from session
        session.pop(session_prefix + '_account_info', None)
        session.pop(session_prefix + '_response', None)

        response_payload = dict(message="Successfully signed up.", code=200)

        next_url = get_session_next_url(remote.name)
        if next_url:
            response_payload["next_url"] = next_url

        return response_handler(
            remote,
            remote_app_config['authorized_redirect_url'],
            payload=response_payload
        )

    account_info = session.get(session_prefix + '_account_info')
    return response_handler(
        remote,
        remote_app_config['signup_redirect_url'],
        payload=dict(
            form=account_info['user'],
            remote=remote.name,
            app_title=remote_app_config.get('title', ''),
            app_description=remote_app_config.get('description', ''),
            app_icon=remote_app_config.get('icon', None),
        ))


def oauth2_handle_error(remote, resp, error_code, error_uri,
                        error_description):
    """Handle errors during exchange of one-time code for an access tokens."""
    remote_app_config = current_app.config['OAUTHCLIENT_REST_REMOTE_APPS'][
        remote.name]
    return response_handler(
        remote,
        remote_app_config['error_redirect_url'],
        payload=dict(
            message="Authorization with remote service failed.",
            code=400
        )
    )
