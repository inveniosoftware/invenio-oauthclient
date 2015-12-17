# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015 CERN.
#
# Invenio is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# Invenio is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Invenio; if not, write to the
# Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston,
# MA 02111-1307, USA.
#
# In applying this license, CERN does not
# waive the privileges and immunities granted to it by virtue of its status
# as an Intergovernmental Organization or submit itself to any jurisdiction.

"""Invenio-OAuthClient provides OAuth web authorization support."""

from __future__ import absolute_import, print_function

from flask_login import user_logged_out
from flask_oauthlib.client import OAuth as FlaskOAuth

from . import config
from .handlers import authorized_default_handler, disconnect_handler, \
    make_handler, make_token_getter, oauth_logout_handler


class _OAuthClientState(object):
    """OAuth client state storing registered actions."""

    def __init__(self, app):
        """Initialize state."""
        self.app = app
        self.handlers = {}
        self.disconnect_handlers = {}
        self.signup_handlers = {}

        # Connect signal to remove access tokens on logout
        user_logged_out.connect(oauth_logout_handler)

        self.oauth = app.extensions.get('oauthlib.client') or FlaskOAuth()

        # Add remote applications
        self.oauth.init_app(app)

        for remote_app, conf in app.config[
                'OAUTHCLIENT_REMOTE_APPS'].items():
            # Prevent double creation problems
            if remote_app not in self.oauth.remote_apps:
                remote = self.oauth.remote_app(
                    remote_app,
                    **conf['params']
                )

            remote = self.oauth.remote_apps[remote_app]

            # Set token getter for remote
            remote.tokengetter(make_token_getter(remote))

            # Register authorized handler
            self.handlers[remote_app] = remote.authorized_handler(make_handler(
                conf.get('authorized_handler', authorized_default_handler),
                remote,
            ))

            # Register disconnect handler
            self.disconnect_handlers[remote_app] = make_handler(
                conf.get('disconnect_handler', disconnect_handler),
                remote,
                with_response=False,
            )

            # Register sign-up handlers
            def dummy_handler(remote, *args, **kargs):
                pass

            signup_handler = conf.get('signup_handler', dict())
            account_info_handler = make_handler(
                signup_handler.get('info', dummy_handler),
                remote,
                with_response=False
            )
            account_setup_handler = make_handler(
                signup_handler.get('setup', dummy_handler),
                remote,
                with_response=False
            )
            account_view_handler = make_handler(
                signup_handler.get('view', dummy_handler),
                remote,
                with_response=False
            )

            self.signup_handlers[remote_app] = dict(
                info=account_info_handler,
                setup=account_setup_handler,
                view=account_view_handler,
            )


class InvenioOAuthClient(object):
    """Invenio Oauthclient extension."""

    def __init__(self, app=None):
        """Extension initialization."""
        if app:
            self._state = self.init_app(app)

    def init_app(self, app):
        """Flask application initialization."""
        self.init_config(app)
        state = _OAuthClientState(app)
        app.extensions['invenio-oauthclient'] = state
        return state

    def init_config(self, app):
        """Initialize configuration."""
        for k in dir(config):
            if k.startswith('OAUTHCLIENT_'):
                app.config.setdefault(k, getattr(config, k))

        app.config.update(
            SECURITY_LOGIN_USER_TEMPLATE="invenio_oauthclient/login_user.html"
        )
