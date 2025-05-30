# -*- coding: utf-8 -*-
#
# Copyright (C) 2020-2021 TU Wien.
# Copyright (C)      2024 Graz University of Technology.
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
        self,
        title,
        description,
        base_url,
        realm,
        app_key=None,
        icon=None,
        scopes="openid",
        legacy_url_path=True,  # for keycloak versions < 17
        **kwargs
    ):
        """The constructor takes two arguments.

        :param base_url: The base URL on which Keycloak is running
                            (e.g. "http://localhost:8080")
        :param realm: Realm in which the invenio client application is defined
        :param legacy_url_path: Add "/auth/" between the base URL and realm names for generated Keycloak URLs (default: True, for Keycloak up to v17)
        """
        app_key = app_key or "KEYCLOAK_APP_CREDENTIALS"
        base_url = "{}/".format(base_url.rstrip("/"))  # add leading `/`

        # Keycloak versions < 17 have default realm url of <base_url>/auth/realms/
        # Newer version omit the /auth portion per default.
        self._realm_url = "{base_url}{realms_part}/{realm}".format(
            base_url=base_url,
            realms_part="auth/realms" if legacy_url_path else "realms",
            realm=realm,
        )

        access_token_url = self.make_url(self._realm_url, "token")
        authorize_url = self.make_url(self._realm_url, "auth")
        self._user_info_url = self.make_url(self._realm_url, "userinfo")

        super().__init__(
            title,
            description,
            base_url,
            app_key,
            icon=icon,
            request_token_params={"scope": scopes},
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
    def make_url(realm_url, endpoint):
        """Create an endpoint URL following the default Keycloak URL schema.

        :param realm_url: The realm base URL
        :param endpoint: The endpoint to use (e.g. "auth", "token", ...)
        """
        return "{}/protocol/openid-connect/{}".format(realm_url, endpoint)

    def get_handlers(self):
        """Return a dict with the auth handlers."""
        return self._handlers

    def get_rest_handlers(self):
        """Return a dict with the auth REST handlers."""
        return self._rest_handlers
