# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2018 CERN.
# Copyright (C) 2024 Graz University of Technology.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Invenio-OAuthClient provides OAuth web authorization support."""

import warnings

from flask import request
from flask_login import user_logged_out
from flask_menu import current_menu
from flask_principal import identity_loaded
from invenio_i18n import LazyString
from invenio_i18n import lazy_gettext as _
from invenio_theme.proxies import current_theme_icons

from . import config, handlers
from .utils import (
    load_or_import_from_config,
    load_user_role_needs,
    obj_or_import_string,
)

from invenio_oauthclient._compat import monkey_patch_werkzeug  # noqa isort:skip

monkey_patch_werkzeug()  # noqa isort:skip

from flask_oauthlib.client import OAuth as FlaskOAuth  # noqa isort:skip
from flask_oauthlib.client import OAuthRemoteApp  # noqa isort:skip


class _OAuthClientState(object):
    """OAuth client state storing registered actions."""

    def __init__(
        self,
        app,
        remote_app_config_key,
        default_disconnect_handler,
        default_authorized_handler,
        default_remote_app_response_handler=None,
        default_response_handler=None,
    ):
        """Initialize state."""
        self.app = app
        self.handlers = {}
        self.disconnect_handlers = {}
        self.signup_handlers = {}
        self.remote_app_response_handler = {}

        # Connect signal to add User/Role needs on identity loaded
        @identity_loaded.connect_via(app)
        def on_identity_loaded(_, identity):
            load_user_role_needs(identity)

        # Connect signal to remove access tokens on logout
        user_logged_out.connect(handlers.oauth_logout_handler)

        self.oauth = app.extensions.get("oauthlib.client") or FlaskOAuth()

        # Init config
        self.init_config(app)

        # Add remote applications
        self.oauth.init_app(app)

        remote_app_class = load_or_import_from_config(
            "OAUTHCLIENT_REMOTE_APP", app, default=OAuthRemoteApp
        )

        def dummy_handler(remote, *args, **kargs):
            pass

        self.default_response_handler = default_response_handler or dummy_handler

        for remote_app, conf in app.config[remote_app_config_key].items():
            # Prevent double creation problems
            if remote_app not in self.oauth.remote_apps:
                # use this app's specific remote app class if there is one.
                current_remote_app_class = obj_or_import_string(
                    conf.get("remote_app"), default=remote_app_class
                )
                # Register the remote app. We are doing this because the
                # current version of OAuth.remote_app does not allow to specify
                # the remote app class. Use it once it is fixed.
                self.oauth.remote_apps[remote_app] = current_remote_app_class(
                    self.oauth, remote_app, **conf["params"]
                )

            remote = self.oauth.remote_apps[remote_app]

            # Set token getter for remote
            remote.tokengetter(handlers.make_token_getter(remote))

            # Register authorized handler
            self.handlers[remote_app] = handlers.authorized_handler(
                handlers.make_handler(
                    conf.get("authorized_handler", default_authorized_handler), remote
                ),
                remote.authorized_response,
            )

            # Register disconnect handler
            self.disconnect_handlers[remote_app] = handlers.make_handler(
                conf.get("disconnect_handler", default_disconnect_handler),
                remote,
                with_response=False,
            )
            self.remote_app_response_handler[remote_app] = obj_or_import_string(
                conf.get(
                    "response_handler",
                    default_remote_app_response_handler or dummy_handler,
                )
            )

            # Register sign-up handlers
            signup_handler = conf.get("signup_handler", dict())
            account_info_handler = handlers.make_handler(
                signup_handler.get("info", dummy_handler), remote, with_response=False
            )
            account_info_serializer_handler = handlers.make_handler(
                signup_handler.get("info_serializer", dummy_handler),
                remote,
                with_response=False,
            )
            account_groups_handler = handlers.make_handler(
                signup_handler.get("groups", dummy_handler), remote, with_response=False
            )
            account_groups_serializer_handler = handlers.make_handler(
                signup_handler.get("groups_serializer", dummy_handler),
                remote,
                with_response=False,
            )
            account_setup_handler = handlers.make_handler(
                signup_handler.get("setup", dummy_handler), remote, with_response=False
            )
            account_view_handler = handlers.make_handler(
                signup_handler.get("view", dummy_handler), remote, with_response=False
            )

            self.signup_handlers[remote_app] = dict(
                info=account_info_handler,
                info_serializer=account_info_serializer_handler,
                groups=account_groups_handler,
                groups_serializer=account_groups_serializer_handler,
                setup=account_setup_handler,
                view=account_view_handler,
            )

        if "cern" in self.oauth.remote_apps:
            warnings.warn(
                "CERN Remote app is deprecated, use CERN OpenID instead.",
                DeprecationWarning,
            )

    def init_config(self, app):
        """Initialize configuration."""
        for k in dir(config):
            if k.startswith("OAUTHCLIENT_"):
                app.config.setdefault(k, getattr(config, k))


class InvenioOAuthClient(object):
    """Invenio Oauthclient extension."""

    def __init__(self, app=None):
        """Extension initialization."""
        if app:
            self._state = self.init_app(app)

    def init_app(self, app):
        """Flask application initialization."""
        state = _OAuthClientState(
            app,
            "OAUTHCLIENT_REMOTE_APPS",
            handlers.disconnect_handler,
            handlers.authorized_default_handler,
        )
        app.extensions["invenio-oauthclient"] = state
        return state


class InvenioOAuthClientREST(object):
    """Invenio Oauthclient extension."""

    def __init__(self, app=None):
        """Extension initialization."""
        if app:
            self._state = self.init_app(app)

    def init_app(self, app):
        """Flask application initialization."""
        _default_response_handler = obj_or_import_string(
            app.config.get("OAUTHCLIENT_REST_DEFAULT_RESPONSE_HANDLER"),
            handlers.rest.default_response_handler,
        )
        _default_remote_handler = handlers.rest.default_remote_response_handler
        state = _OAuthClientState(
            app,
            "OAUTHCLIENT_REST_REMOTE_APPS",
            handlers.rest.disconnect_handler,
            handlers.rest.authorized_default_handler,
            default_remote_app_response_handler=_default_remote_handler,
            default_response_handler=_default_response_handler,
        )

        app.extensions["invenio-oauthclient"] = state
        return state


def finalize_app(app):
    """Finalize app."""
    override_template_configuration(app)
    init_index_menu(app)
    post_ext_init(app)


def override_template_configuration(app):
    """Override template configuration."""
    template_key = app.config.get(
        "OAUTHCLIENT_TEMPLATE_KEY",
        "SECURITY_LOGIN_USER_TEMPLATE",  # default template key
    )
    if template_key is not None:
        template = app.config[template_key]  # keep the old value
        app.config["OAUTHCLIENT_LOGIN_USER_TEMPLATE_PARENT"] = template
        app.config[template_key] = app.config.get(
            "OAUTHCLIENT_LOGIN_USER_TEMPLATE",
            "invenio_oauthclient/login_user.html",
        )


def init_index_menu(app):
    """Init index menu."""

    def active_when():
        return request.endpoint.startswith("invenio_oauthclient_settings.")

    def visible_when():
        return bool(app.config.get("OAUTHCLIENT_REMOTE_APPS")) is not False

    current_menu.submenu("settings.oauthclient").register(
        "invenio_oauthclient_settings.index",
        _(
            "%(icon)s Linked accounts",
            icon=LazyString(lambda: f'<i class="{current_theme_icons.link}"></i>'),
        ),
        order=3,
        active_when=active_when,
        visible_when=visible_when,
    )

    current_menu.submenu("breadcrumbs.settings.oauthclient").register(
        "invenio_oauthclient_settings.index",
        _("Linked accounts"),
    )


def post_ext_init(app):
    """Setup blueprint."""
    app.config.setdefault(
        "OAUTHCLIENT_SITENAME",
        app.config.get("THEME_SITENAME", "Invenio"),
    )
    app.config.setdefault(
        "OAUTHCLIENT_BASE_TEMPLATE",
        app.config.get("BASE_TEMPLATE", "invenio_oauthclient/base.html"),
    )
    app.config.setdefault(
        "OAUTHCLIENT_COVER_TEMPLATE",
        app.config.get("COVER_TEMPLATE", "invenio_oauthclient/base_cover.html"),
    )
    app.config.setdefault(
        "OAUTHCLIENT_SETTINGS_TEMPLATE",
        app.config.get("SETTINGS_TEMPLATE", "invenio_oauthclient/settings/base.html"),
    )
