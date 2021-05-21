# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Client blueprint used to handle OAuth callbacks."""

from flask import Blueprint, abort, current_app, redirect, request, url_for
from flask_oauthlib.client import OAuthException
from invenio_accounts.views import login as base_login
from invenio_db import db
from itsdangerous import BadData

from .._compat import _create_identifier
from ..errors import OAuthRemoteNotFound
from ..handlers import set_session_next_url
from ..handlers.rest import response_handler
from ..proxies import current_oauthclient
from ..utils import get_safe_redirect_target, serializer

blueprint = Blueprint(
    'invenio_oauthclient',
    __name__,
    url_prefix='/oauth',
    static_folder='../static',
    template_folder='../templates',
)


rest_blueprint = Blueprint(
    'invenio_oauthclient',
    __name__,
    url_prefix='/oauth',
    static_folder='../static',
    template_folder='../templates',
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


@blueprint.route("/login")
def auto_redirect_login(*args, **kwargs):
    """Handles automatic redirect to external auth service.

    The login endpoint will redirect automatically to the external
    auth service is the following conditions are met:

    * local login is disabled
    * redirect to external login is enabled
    * only one external auth service is configured

    This function should be set as value of the invenio-accounts
    config var ``ACCOUNTS_LOGIN_VIEW_FUNCTION``. It should be defined in
    the Invenio application configuration to ensure that is correctly loaded.
    """
    local_login_enabled = current_app.config.get(
        "ACCOUNTS_LOCAL_LOGIN_ENABLED", False
    )
    auto_redirect_enabled = current_app.config.get(
        "OAUTHCLIENT_AUTO_REDIRECT_TO_EXTERNAL_LOGIN", False
    )
    would_redirect = auto_redirect_enabled and not local_login_enabled
    remote_apps = list(current_oauthclient.oauth.remote_apps)

    if would_redirect and len(remote_apps) == 1:
        # if local login is disabled and we only have one OAuth2 remote app
        # configured, we forward directly to that
        url = url_for("invenio_oauthclient.login", remote_app=remote_apps[0])
        return redirect(url)

    else:
        return base_login(*args, **kwargs)


def _login(remote_app, authorized_view_name):
    """Send user to remote application for authentication."""
    oauth = current_oauthclient.oauth
    if remote_app not in oauth.remote_apps:
        raise OAuthRemoteNotFound()

    # Get redirect target in safe manner.
    next_param = get_safe_redirect_target(arg='next')

    # Redirect URI - must be registered in the remote service.
    callback_url = url_for(
        authorized_view_name,
        remote_app=remote_app,
        _external=True,
        _scheme="https"
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


@blueprint.route('/login/<remote_app>/')
def login(remote_app):
    """Send user to remote application for authentication."""
    try:
        return _login(remote_app, '.authorized')
    except OAuthRemoteNotFound:
        return abort(404)


@rest_blueprint.route('/login/<remote_app>/')
def rest_login(remote_app):
    """Send user to remote application for authentication."""
    try:
        return _login(remote_app, '.rest_authorized')
    except OAuthRemoteNotFound:
        abort(404)


def _authorized(remote_app=None):
    """Authorized handler callback."""
    if remote_app not in current_oauthclient.handlers:
        return abort(404)

    state_token = request.args.get('state')

    # Verify state parameter
    assert state_token
    # Checks authenticity and integrity of state and decodes the value.
    state = serializer.loads(state_token)
    # Verify that state is for this session, app and that next parameter
    # have not been modified.
    assert state['sid'] == _create_identifier()
    assert state['app'] == remote_app
    # Store next URL
    set_session_next_url(remote_app, state['next'])

    handler = current_oauthclient.handlers[remote_app]()
    return handler


@blueprint.route('/authorized/<remote_app>/')
def authorized(remote_app=None):
    """Authorized handler callback."""
    try:
        return _authorized(remote_app)
    except OAuthRemoteNotFound:
        return abort(404)
    except (AssertionError, BadData):
        if current_app.config.get('OAUTHCLIENT_STATE_ENABLED', True) or (
           not(current_app.debug or current_app.testing)):
            abort(403)
    except OAuthException as e:
        if e.type == 'invalid_response':
            current_app.logger.warning(
                '{message} ({data})'.format(
                    message=e.message,
                    data=e.data
                )
            )
            abort(500)
        else:
            raise


@rest_blueprint.route('/authorized/<remote_app>/')
def rest_authorized(remote_app=None):
    """Authorized handler callback."""
    try:
        return _authorized(remote_app)
    except OAuthRemoteNotFound:
        abort(404)
    except (AssertionError, BadData) as e:
        current_app.logger.error(str(e))
        if current_app.config.get('OAUTHCLIENT_STATE_ENABLED', True) or (
           not(current_app.debug or current_app.testing)):
            return response_handler(
                None,
                current_app.config[
                    'OAUTHCLIENT_REST_DEFAULT_ERROR_REDIRECT_URL'],
                payload=dict(
                    message="Invalid state.",
                    code=403
                    )
                )
    except OAuthException as e:
        current_app.logger.error(str(e))
        if e.type == 'invalid_response':
            return response_handler(
                None,
                current_app.config[
                    'OAUTHCLIENT_REST_DEFAULT_ERROR_REDIRECT_URL'],
                payload=dict(
                    message="Invalid response.",
                    code=500
                )
            )
        else:
            raise


def _signup(remote_app):
    """Extra signup step."""
    if remote_app not in current_oauthclient.signup_handlers:
        raise OAuthRemoteNotFound()
    return current_oauthclient.signup_handlers[remote_app]['view']()


@blueprint.route('/signup/<remote_app>/', methods=['GET', 'POST'])
def signup(remote_app):
    """Extra signup step."""
    try:
        res = _signup(remote_app)
        return abort(404) if res is None else res
    except OAuthRemoteNotFound:
        return abort(404)


@rest_blueprint.route('/signup/<remote_app>/', methods=['GET', 'POST'])
def rest_signup(remote_app):
    """Extra signup step."""
    try:
        res = _signup(remote_app)
        return abort(404) if res is None else res
    except OAuthRemoteNotFound:
        abort(404)


def _disconnect(remote_app):
    """Extra signup step."""
    if remote_app not in current_oauthclient.signup_handlers:
        raise OAuthRemoteNotFound()
    ret = current_oauthclient.disconnect_handlers[remote_app]()
    db.session.commit()
    return ret


@blueprint.route('/disconnect/<remote_app>/')
def disconnect(remote_app):
    """Disconnect user from remote application.

    Removes application as well as associated information.
    """
    try:
        return _disconnect(remote_app)
    except OAuthRemoteNotFound:
        abort(404)


@rest_blueprint.route('/disconnect/<remote_app>/')
def rest_disconnect(remote_app):
    """Disconnect user from remote application.

    Removes application as well as associated information.
    """
    try:
        return _disconnect(remote_app)
    except OAuthRemoteNotFound:
        abort(404)
