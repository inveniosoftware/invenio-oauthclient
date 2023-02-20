# -*- coding: utf-8 -*-
#
# Copyright (C) 2020-2021 TU Wien.
#
# Invenio-Keycloak is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Pre-defined defaults and helpers for Invenio-Keycloak configuration."""

from invenio_oauthclient.contrib.settings import OAuthSettingsHelper


class KeycloakSettingsHelper(OAuthSettingsHelper):
    """Helper for creating REMOTE_APP configuration dictionaries for Keycloak.

    This class can be used to easily create a base configuration with sensible
    defaults for a default-ish Keycloak setup.
    It requires knowledge about the base URL of the Keycloak instance and the
    realm on which the Invenio client application is configured.
    Because the default endpoint URLs follow a simple schema, this information
    can be used to create a simple base configuration.

    The methods ``remote_app()`` and ``remote_rest_app()`` create and return
    a dictionary in the form expected by Invenio-OAuthClient.
    The latter can be used for providing SSO capabilities to SPAs communicating
    with Invenio via the REST API.

    Further, the helper provides some properties for commonly used default
    endpoint URLs.
    """

    def __init__(
        self, title, base_url, no_url_modification=False, description=None, realm=None, app_key=None, icon=None, **kwargs
    ):
        """The constructor takes two required arguments, title and base_url. Addtionall parameters can be passed to the constructor to override the default values.
        
        :param title: The title of the client application
        :param base_url: The base URL on which Keycloak is running
                            (e.g. "http://localhost:8080")
        :param no_url_modification: If True, the URL will only consist of the base URL and endpoint
        :description: The description of the client application
        :param realm: Realm in which the invenio client application is defined
        :param app_key: The key to use for the client application credentials
        :param icon: The icon to use for the client application
        """
        app_key = app_key or "KEYCLOAK_APP_CREDENTIALS"
        base_url = "{}/".format(base_url.rstrip("/"))  # add leading `/`

        if realm is None:
            self._realm_url = base_url.rstrip("/")
        else:
            self._realm_url = "{}auth/realms/{}".format(base_url, realm)

        access_token_url = self.make_url(self._realm_url, "token", no_url_modification)
        authorize_url = self.make_url(self._realm_url, "auth", no_url_modification)
        self._user_info_url = self.make_url(self._realm_url, "userinfo", no_url_modification)

        super().__init__(
            title,
            description,
            base_url,
            app_key,
            icon=icon,
            request_token_params={"scope": "openid"},
            access_token_url=access_token_url,
            authorize_url=authorize_url,
            **kwargs
        )

        self._handlers = dict(
            authorized_handler="invenio_oauthclient.handlers:authorized_signup_handler",
            disconnect_handler="invenio_oauthclient.contrib.keycloak.handlers:disconnect_handler",
            signup_handler=dict(
                info="invenio_oauthclient.contrib.keycloak.handlers:info_handler",
                info_serializer="invenio_oauthclient.contrib.keycloak.handlers:info_serializer_handler",
                setup="invenio_oauthclient.contrib.keycloak.handlers:setup_handler",
                view="invenio_oauthclient.handlers:signup_handler",
            ),
        )

        self._rest_handlers = dict(
            authorized_handler="invenio_oauthclient.handlers.rest:authorized_signup_handler",
            disconnect_handler="invenio_oauthclient.contrib.keycloak.handlers:disconnect_rest_handler",
            signup_handler=dict(
                info="invenio_oauthclient.contrib.keycloak.handlers:info_handler",
                info_serializer="invenio_oauthclient.contrib.keycloak.handlers:info_serializer_handler",
                setup="invenio_oauthclient.contrib.keycloak.handlers:setup_handler",
                view="invenio_oauthclient.handlers.rest:signup_handler",
            ),
            response_handler=(
                "invenio_oauthclient.handlers.rest:default_remote_response_handler"
            ),
            authorized_redirect_url="/",
            disconnect_redirect_url="/",
            signup_redirect_url="/",
            error_redirect_url="/",
        )

    @property
    def user_info_url(self):
        """URL for the user info endpoint."""
        return self._user_info_url

    @property
    def realm_url(self):
        """URL for the realm's endpoint."""
        return self._realm_url

    @staticmethod
    def make_url(realm_url, endpoint, no_url_modification):
        """Create an endpoint URL following the default Keycloak URL schema, with the option to disable URL modification and only use the base URL and endpoint.
        
        :param realm_url: The realm base URL
        :param endpoint: The endpoint to use (e.g. "auth", "token", ...)
        :param no_url_modification: If True, the URL will only consist of the base URL and endpoint
        """
        if no_url_modification is False:
            return "{}/protocol/openid-connect/{}".format(realm_url, endpoint)
        else:
            return"{}/{}".format(realm_url, endpoint)

    def get_handlers(self):
        """Return a dict with the auth handlers."""
        return self._handlers

    def get_rest_handlers(self):
        """Return a dict with the auth REST handlers."""
        return self._rest_handlers
