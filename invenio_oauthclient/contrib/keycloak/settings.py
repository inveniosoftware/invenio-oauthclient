# -*- coding: utf-8 -*-
#
# Copyright (C) 2020-2021 TU Wien.
#
# Invenio-Keycloak is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Pre-defined defaults and helpers for Invenio-Keycloak configuration."""


class KeycloakSettingsHelper:
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

    def __init__(self, base_url, realm):
        """The constructor takes two arguments.

        :param base_url: The base URL on which Keycloak is running
                            (e.g. "http://localhost:8080")
        :param realm: Realm in which the invenio client application is defined
        """
        self.base_url = base_url
        self.realm = realm
        self._access_token_url = self.make_url("token")
        self._authorize_url = self.make_url("auth")
        self._user_info_url = self.make_url("userinfo")
        self._realm_url = self.make_realm_url()

    @property
    def access_token_url(self):
        """URL for the access token endpoint."""
        return self._access_token_url

    @property
    def authorize_url(self):
        """URL for the authorization endpoint."""
        return self._authorize_url

    @property
    def user_info_url(self):
        """URL for the user info endpoint."""
        return self._user_info_url

    @property
    def realm_url(self):
        """URL for the realm's endpoint."""
        return self._realm_url

    def make_realm_url(self):
        """Create a URL pointing towards the Keycloak realm."""
        base_url = self.base_url.rstrip("/")
        return "{}/auth/realms/{}".format(base_url, self.realm)

    def make_url(self, endpoint):
        """Create an endpoint URL following the default Keycloak URL schema.

        :param endpoint: The endpoint to use (e.g. "auth", "token", ...)
        """
        return "{}/protocol/openid-connect/{}" \
            .format(self.make_realm_url(), endpoint)

    def remote_app(self):
        """Create a KEYCLOAK_REMOTE_APP using the given base URL and realm."""
        return dict(
            title="Keycloak",
            description="Your local keycloak installation",
            icon="",

            authorized_handler="invenio_oauthclient.handlers"
                               ":authorized_signup_handler",
            disconnect_handler="invenio_oauthclient.contrib.keycloak.handlers"
                               ":disconnect_handler",
            signup_handler=dict(
                info="invenio_oauthclient.contrib.keycloak.handlers"
                     ":info_handler",
                setup="invenio_oauthclient.contrib.keycloak.handlers"
                     ":setup_handler",
                view="invenio_oauthclient.handlers:signup_handler"
            ),

            params=dict(
                base_url=self.base_url,

                request_token_params={"scope": "openid"},
                request_token_url=None,

                access_token_url=self.access_token_url,
                access_token_method="POST",

                authorize_url=self.authorize_url,
                app_key="KEYCLOAK_APP_CREDENTIALS",
            )
        )

    def remote_rest_app(self):
        """Crete a KEYCLOAK_REMOTE_REST_APP using the given configuration."""
        return self.remote_app().update(dict(
            authorized_handler="invenio_oauthclient.handlers.rest"
                               ":authorized_signup_handler",
            disconnect_handler="invenio_oauthclient.contrib.keycloak.handlers"
                               ":disconnect_rest_handler",
            signup_handler=dict(
                info="invenio_oauthclient.contrib.keycloak.handlers"
                     ":info_handler",
                setup="invenio_oauthclient.contrib.keycloak.handlers"
                      ":setup_handler",
                view="invenio_oauthclient.handlers.rest:signup_handler"
            ),

            response_handler=(
                "invenio_oauthclient.handlers.rest"
                ":default_remote_response_handler"
            ),

            authorized_redirect_url="/",
            disconnect_redirect_url="/",
            signup_redirect_url="/",
            error_redirect_url="/"
        ))


helper = KeycloakSettingsHelper("https://locahost:8080", "invenio")
OAUTHCLIENT_KEYCLOAK_REALM_URL = helper.realm_url
OAUTHCLIENT_KEYCLOAK_USER_INFO_URL = helper.user_info_url
OAUTHCLIENT_KEYCLOAK_REMOTE_APP = helper.remote_app()
OAUTHCLIENT_KEYCLOAK_REMOTE_REST_APP = helper.remote_rest_app()
OAUTHCLIENT_KEYCLOAK_VERIFY_AUD = True
OAUTHCLIENT_KEYCLOAK_VERIFY_EXP = True
OAUTHCLIENT_KEYCLOAK_AUD = "invenio"
