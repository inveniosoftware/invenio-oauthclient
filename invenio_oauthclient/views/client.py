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
from itsdangerous import BadData, TimedJSONWebSignatureSerializer
from werkzeug.local import LocalProxy

from .._compat import _create_identifier
from ..handlers import set_session_next_url
from ..proxies import current_oauthclient
from ..utils import get_safe_redirect_target

blueprint = Blueprint(
    'invenio_oauthclient',
    __name__,
    url_prefix='/oauth',
    static_folder='../static',
    template_folder='../templates',
)


serializer = LocalProxy(
    lambda: TimedJSONWebSignatureSerializer(
        current_app.config['SECRET_KEY'],
        expires_in=current_app.config['OAUTHCLIENT_STATE_EXPIRES'],
    )
)


@blueprint.record_once
def post_ext_init(state):
    """Setup blueprint."""
    app = state.app

    app.config.setdefault(
        'OAUTHCLIENT_SITENAME',
        app.config.get('THEME_SITENAME', 'Invenio'))
    app.config.setdefault(
        'OAUTHCLIENT_BASE_TEMPLATE',
        app.config.get('BASE_TEMPLATE',
                       'invenio_oauthclient/base.html'))
    app.config.setdefault(
        'OAUTHCLIENT_COVER_TEMPLATE',
        app.config.get('COVER_TEMPLATE',
                       'invenio_oauthclient/base_cover.html'))
    app.config.setdefault(
        'OAUTHCLIENT_SETTINGS_TEMPLATE',
        app.config.get('SETTINGS_TEMPLATE',
                       'invenio_oauthclient/settings/base.html'))


@blueprint.route('/login/<remote_app>/')
def login(remote_app):
    """Send user to remote application for authentication."""
    oauth = current_app.extensions['oauthlib.client']

    if remote_app not in oauth.remote_apps:
        return abort(404)

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
    if remote_app not in current_oauthclient.handlers:
        return abort(404)

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
            abort(403)

    try:
        handler = current_oauthclient.handlers[remote_app]()
    except OAuthException as e:
        if e.type == 'invalid_response':
            abort(500)
        else:
            raise

    return handler


@blueprint.route('/signup/<remote_app>/', methods=['GET', 'POST'])
def signup(remote_app):
    """Extra signup step."""
    if remote_app not in current_oauthclient.signup_handlers:
        return abort(404)
    res = current_oauthclient.signup_handlers[remote_app]['view']()
    return abort(404) if res is None else res


@blueprint.route('/disconnect/<remote_app>/')
def disconnect(remote_app):
    """Disconnect user from remote application.

    Removes application as well as associated information.
    """
    if remote_app not in current_oauthclient.disconnect_handlers:
        return abort(404)

    ret = current_oauthclient.disconnect_handlers[remote_app]()
    db.session.commit()
    return ret
