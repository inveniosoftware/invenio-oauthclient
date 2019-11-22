# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Client blueprint used to handle OAuth callbacks."""

from __future__ import absolute_import

from flask import Blueprint, abort, current_app, flash, redirect, request, \
    url_for
from flask_oauthlib.client import OAuthException
from invenio_db import db
from itsdangerous import BadData
from werkzeug.local import LocalProxy

from invenio_oauthclient._compat import _create_identifier
from invenio_oauthclient.handlers import set_session_next_url
from invenio_oauthclient.handlers.rest import response_handler
from invenio_oauthclient.proxies import current_oauthclient
from invenio_oauthclient.utils import get_safe_redirect_target

from ..utils import serializer

blueprint = Blueprint(
    'invenio_oauthclient',
    __name__,
    url_prefix='/oauth',
    static_folder='../static',
    template_folder='../templates',
)


@blueprint.route('/login/<remote_app>/')
def login(remote_app):
    """Send user to remote application for authentication."""
    oauth = current_app.extensions['oauthlib.client']
    remote_app_config = current_app.config['OAUTHCLIENT_REST_REMOTE_APPS'][
        remote_app]

    if remote_app not in oauth.remote_apps:
        return response_handler(
            remote_app,
            remote_app_config['error_redirect_url'],
            payload=dict(
                message="Remote {} not found.".format(remote_app),
                code=404
            ))

    # Get redirect target in safe manner.
    next_param = get_safe_redirect_target(arg='next')

    # Redirect URI - must be registered in the remote service.
    callback_url = url_for(
        '.authorized',
        remote_app=remote_app,
        _external=True,
    )

    # Create a JSON Web Token that expires after OAUTHCLIENT_STATE_EXPIRES
    # seconds.
    state_token = serializer.dumps({
        'app': remote_app,
        'next': next_param,
        'sid': _create_identifier(),
    })

    return oauth.remote_apps[remote_app].authorize(
        callback=callback_url,
        state=state_token,
    )


@blueprint.route('/authorized/<remote_app>/')
def authorized(remote_app=None):
    """Authorized handler callback."""
    remote_app_config = current_app.config['OAUTHCLIENT_REST_REMOTE_APPS'][
        remote_app]
    if remote_app not in current_oauthclient.handlers:
        return response_handler(
            remote_app,
            remote_app_config['error_redirect_url'],
            payload=dict(
                message="Handler for remote {} not found.".format(remote_app),
                code=404
            )
        )

    state_token = request.args.get('state')

    # Verify state parameter
    try:
        assert state_token
        # Checks authenticity and integrity of state and decodes the value.
        state = serializer.loads(state_token)
        # Verify that state is for this session, app and that next parameter
        # have not been modified.
        assert state['sid'] == _create_identifier()
        assert state['app'] == remote_app
        # Store next URL
        set_session_next_url(remote_app, state['next'])
    except (AssertionError, BadData):
        if current_app.config.get('OAUTHCLIENT_STATE_ENABLED', True) or (
           not(current_app.debug or current_app.testing)):
            return response_handler(
                remote_app,
                remote_app_config['error_redirect_url'],
                payload=dict(
                    message="Invalid state.",
                    code=403
                )
            )

    try:
        handler = current_oauthclient.handlers[remote_app]()
    except OAuthException as e:
        return response_handler(
            remote_app,
            remote_app_config['error_redirect_url'],
            payload=dict(
                message="Invalid response.",
                code=500
            )
        )
    return handler


@blueprint.route('/signup/<remote_app>/', methods=['GET', 'POST'])
def signup(remote_app):
    """Extra signup step."""
    remote_app_config = current_app.config['OAUTHCLIENT_REST_REMOTE_APPS'][
        remote_app]
    if remote_app not in current_oauthclient.signup_handlers:
        return response_handler(
            remote_app,
            remote_app_config['error_redirect_url'],
            payload=dict(
                message="Remote {} not found.".format(remote_app),
                code=404
            )
        )
    return current_oauthclient.signup_handlers[remote_app]['view']()


@blueprint.route('/disconnect/<remote_app>/')
def disconnect(remote_app):
    """Disconnect user from remote application.

    Removes application as well as associated information.
    """
    remote_app_config = current_app.config['OAUTHCLIENT_REST_REMOTE_APPS'][
        remote_app]
    if remote_app not in current_oauthclient.disconnect_handlers:
        return response_handler(
            remote_app,
            remote_app_config['error_redirect_url'],
            payload=dict(
                message="Handler for remote {} not found.".format(remote_app),
                code=404
            )
        )

    ret = current_oauthclient.disconnect_handlers[remote_app]()
    db.session.commit()
    return ret
