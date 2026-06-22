# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2025-2026 Front Matter.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Pre-configured remote application for enabling sign in/up with OIDC providers.

This is a generic OpenID Connect (OIDC) implementation that works with any
OIDC-compliant identity provider such as Authentik, Keycloak, Auth0, Okta, etc.

1. Edit your configuration and add:

   .. code-block:: python

        from invenio_oauthclient.contrib import oidc

        OAUTHCLIENT_REMOTE_APPS = dict(
            oidc=oidc.REMOTE_APP,
        )

        OIDC_APP_CREDENTIALS = dict(
            consumer_key='changeme',
            consumer_secret='changeme',
        )

2. Register a new OAuth2/OpenID Provider application in your OIDC provider.
   When registering the application ensure that the *Redirect URIs* includes:
   ``http://localhost:5000/oauth/authorized/oidc/``

   For production deployments:
   ``https://yourdomain.com/oauth/authorized/oidc/``

3. Configure the application in your OIDC provider:
   - Provider type: OAuth2/OpenID Provider
   - Client type: Confidential
   - Authorization grant type: Authorization Code
   - Redirect URIs: Add your callback URL
   - Scopes: openid profile email

4. Grab the *Client ID* and *Client Secret* after registering the application
   and add them to your instance configuration (``invenio.cfg``):

   .. code-block:: python

        OIDC_APP_CREDENTIALS = dict(
            consumer_key='<CLIENT ID>',
            consumer_secret='<CLIENT SECRET>',
        )

5. Configure the OIDC provider issuer in your configuration:

   .. code-block:: python

        OIDC_ISSUER = 'https://your-oidc-provider.com'

   Some OIDC providers require HTTP Basic Authentication for the token endpoint
   instead of sending credentials in the POST body. Enable it with:

   .. code-block:: python

        OIDC_USE_BASIC_AUTH = True

   For Keycloak with realms:

   .. code-block:: python

        OIDC_ISSUER = 'https://keycloak.example.com/realms/master'

   Alternatively, you can set it via environment variable:

   .. code-block:: bash

        export OIDC_ISSUER='https://your-oidc-provider.com'

   When using the module-level REMOTE_APP constants, the issuer is retrieved
   from OIDC_ISSUER configuration in the following order:
   1. Flask app config (current_app.config['OIDC_ISSUER'])
   2. Environment variable (OIDC_ISSUER)

   Note: When instantiating OIDCSettingsHelper directly, you must
   provide issuer as a required parameter - no default value is assumed.

   The module automatically discovers OAuth/OIDC endpoints using the
   OpenID Connect Discovery specification (RFC 8414). Per OIDC spec,
   the discovery document is located at {issuer}/.well-known/openid-configuration.
   If discovery fails, you must provide endpoints manually.

6. Now go to your site: http://localhost:5000/oauth/login/oidc/

7. You should see your OIDC provider listed under Linked accounts:
   http://localhost:5000/account/settings/linkedaccounts/

If you want to customize the OAuth provider or instantiate it directly,
you must provide the issuer parameter (required, no default):

.. code-block:: python

        from invenio_oauthclient.contrib import oidc

        # Simple issuer
        _my_app = oidc.OIDCSettingsHelper(
            issuer="https://your-oidc-provider.com",  # Required parameter
            title="My OIDC Provider",  # Optional
            description="Custom description",  # Optional
            use_discovery=True  # Optional, enable OIDC discovery (default: True)
        )

        # Keycloak with realm
        _keycloak_app = oidc.OIDCSettingsHelper(
            issuer="https://keycloak.example.com/realms/master",
            title="Keycloak",
        )

        # Authentik with application
        _authentik_app = oidc.OIDCSettingsHelper(
            issuer="https://auth.example.com/application/o/myapp",
            title="Authentik",
        )

        OAUTHCLIENT_REMOTE_APPS = dict(
            oidc=_my_app.remote_app,
        )

        OIDC_APP_CREDENTIALS = dict(
            consumer_key='changeme',
            consumer_secret='changeme',
        )

The module supports OpenID Connect Discovery (RFC 8414) to automatically
configure OAuth/OIDC endpoints. Set ``use_discovery=False`` to manually
specify endpoints or if your OIDC provider instance doesn't expose the discovery
endpoint.
"""

import os
from urllib.parse import urlparse

import requests
from flask import current_app, redirect, session, url_for
from flask_login import current_user
from invenio_db import db
from invenio_i18n import lazy_gettext as _
from werkzeug.local import LocalProxy

from invenio_oauthclient import current_oauthclient
from invenio_oauthclient.contrib.settings import OAuthSettingsHelper
from invenio_oauthclient.errors import OAuthResponseError
from invenio_oauthclient.handlers.rest import response_handler
from invenio_oauthclient.handlers.utils import require_more_than_one_external_account
from invenio_oauthclient.models import RemoteAccount
from invenio_oauthclient.oauth import oauth_link_external_id, oauth_unlink_external_id

# Cache for OIDC discovery documents to avoid repeated network requests
_discovery_cache = {}

# Cache for JWKS (JSON Web Key Set) documents
_jwks_cache = {}


class OIDCSettingsHelper(OAuthSettingsHelper):
    """Default configuration for OIDC OAuth provider."""

    def __init__(
        self,
        title=None,
        description=None,
        issuer=None,
        app_key=None,
        icon=None,
        access_token_url=None,
        authorize_url=None,
        logout_url=None,
        precedence_mask=None,
        signup_options=None,
        use_discovery=True,
        use_basic_auth=False,
        scope="openid profile email",
    ):
        """Constructor.

        :param title: Title of the OAuth provider.
        :param description: Description of the OAuth provider.
        :param issuer: The issuer identifier URL (required).
                      Per OIDC spec, this is the authorization server identifier.
                      Examples: 'https://auth.example.com' or 'https://auth.example.com/realms/myrealm'
                      Discovery URL is {issuer}/.well-known/openid-configuration.
        :param app_key: Flask config key for OAuth credentials.
        :param icon: Icon name for the provider (e.g., 'openid', 'discord').
        :param access_token_url: OAuth token endpoint URL (auto-configured via discovery if not provided).
        :param authorize_url: OAuth authorization endpoint URL (auto-configured via discovery if not provided).
        :param logout_url: Logout endpoint URL (auto-configured via discovery if not provided).
        :param precedence_mask: Dict specifying which user info fields take precedence.
        :param signup_options: Dict with signup configuration options.
        :param use_discovery: Whether to use OIDC discovery (RFC 8414) to
                      auto-configure endpoints. Defaults to True.
        :param use_basic_auth: Whether to use HTTP Basic Authentication
                      (client_secret_basic) for the token endpoint instead of
                      sending credentials in the request body
                      (client_secret_post). Some OIDC providers require this.
                      Defaults to False.
        :param scope: OAuth scope to request. Defaults to "openid profile email".
        """
        if not issuer:
            raise ValueError("issuer is required for OIDC OAuth configuration")

        # Store issuer and extract base_url for OAuth parent class
        self.issuer = issuer

        # Set default title and icon based on popular OIDC issuers
        if issuer == "https://discord.com":
            title = title or "Discord"
            icon = icon or "discord"
        elif issuer == "https://github.com/login/oauth":
            title = title or "GitHub"
            icon = icon or "github"
        elif issuer == "https://gitlab.com":
            title = title or "Gitlab"
            icon = icon or "gitlab"
        elif issuer == "https://accounts.google.com":
            title = title or "Google"
            icon = icon or "google"
        elif issuer == "https://orcid.org/":
            title = title or "ORCID"
            icon = icon or "orcid"
            signup_options = signup_options or {
                "auto_confirm": False,
                "send_register_msg": True,
            }
        elif issuer == "https://slack.com":
            title = title or "Slack"
            icon = icon or "slack"

        # issuers used by Invenio instances
        elif issuer == "https://auth.front-matter.de/realms/main":
            title = title or "Front Matter"
            icon = icon or "plug"
            signup_options = signup_options or {"auto_confirm": True}

        # Extract base_url from issuer (scheme + netloc)
        parsed = urlparse(self.issuer)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Try OIDC discovery if enabled
        self._discovery_doc = None
        if use_discovery:
            try:
                self._discovery_doc = self._fetch_oidc_discovery(self.issuer)
                if self._discovery_doc:
                    # Explicit URLs take precedence, use discovered values as fallback
                    access_token_url = access_token_url or self._discovery_doc.get(
                        "token_endpoint"
                    )
                    authorize_url = authorize_url or self._discovery_doc.get(
                        "authorization_endpoint"
                    )
                    logout_url = logout_url or self._discovery_doc.get(
                        "end_session_endpoint"
                    )

                    # Extract supported scopes from discovery and merge with requested scopes
                    # if available.
                    if "scopes_supported" in self._discovery_doc:
                        supported_scopes = set(self._discovery_doc["scopes_supported"])
                        requested_scopes = set(scope.split())

                        # Use only requested scopes that are actually supported
                        available_scopes = requested_scopes.intersection(
                            supported_scopes
                        )

                        # Always include openid as it's required for OIDC
                        available_scopes.add("openid")

                        # Update scope to only include supported scopes
                        scope = " ".join(sorted(available_scopes))
            except Exception as e:
                # Log warning but continue with manual configuration
                try:
                    current_app.logger.warning(
                        f"OIDC discovery failed for {self.issuer}: {str(e)}. "
                        f"Using manual endpoint configuration."
                    )
                except RuntimeError:
                    # No app context available, silently continue
                    pass

        # Use standard OIDC paths as fallback if discovery failed or disabled
        # and no explicit URLs were provided
        if not access_token_url or not authorize_url or not logout_url:
            # Special handling for Authentik-style paths: /application/o/{app}/
            # For these, endpoints should be at /application/o/ (without the app name)
            endpoint_base = self._get_endpoint_base(self.issuer)

            # Keycloak uses /protocol/openid-connect/{auth,token,logout}
            if "/realms/" in self.issuer:
                oidc_base = f"{self.issuer.rstrip('/')}/protocol/openid-connect"
                access_token_url = access_token_url or f"{oidc_base}/token"
                authorize_url = authorize_url or f"{oidc_base}/auth"
                logout_url = logout_url or f"{oidc_base}/logout"
            else:
                # Most OIDC providers follow the standard paths, but some providers
                # may have different structures. Configure endpoints manually if needed.
                access_token_url = access_token_url or f"{endpoint_base}/token"
                authorize_url = authorize_url or f"{endpoint_base}/authorize"
                logout_url = logout_url or f"{endpoint_base}/logout"

        precedence_mask = precedence_mask or {
            "email": True,
            "profile": {
                "username": True,
                "full_name": True,
            },
        }

        signup_options = signup_options or {
            "auto_confirm": False,
            "send_register_msg": False,
        }

        # Build extra kwargs for the OAuth library
        extra_params = {}
        if use_basic_auth:
            # Instructs the OAuth library (Authlib) to send client credentials
            # via the HTTP Authorization header (RFC 6749 §2.3.1) rather than
            # in the POST body ('client_secret_post').
            extra_params["token_endpoint_auth_method"] = "client_secret_basic"

        super().__init__(
            title or _("OpenID Connect (OIDC)"),
            description
            or _(
                "OpenID Connect allows third-party applications to verify the identity of the end-user and to obtain basic user profile information."
            ),
            base_url=base_url,
            app_key=app_key or "OIDC_APP_CREDENTIALS",
            icon=icon or "openid",
            request_token_params={"scope": scope},
            access_token_url=access_token_url,
            authorize_url=authorize_url,
            logout_url=logout_url,
            content_type="application/json",
            precedence_mask=precedence_mask,
            signup_options=signup_options,
            **extra_params,
        )

        self._handlers = dict(
            authorized_handler="invenio_oauthclient.handlers:authorized_signup_handler",
            disconnect_handler="invenio_oauthclient.contrib.oidc:disconnect_handler",
            signup_handler=dict(
                info="invenio_oauthclient.contrib.oidc:account_info",
                info_serializer="invenio_oauthclient.contrib.oidc:account_info_serializer",
                setup="invenio_oauthclient.contrib.oidc:account_setup",
                view="invenio_oauthclient.handlers:signup_handler",
            ),
        )

        self._rest_handlers = dict(
            authorized_handler="invenio_oauthclient.handlers.rest:authorized_signup_handler",
            disconnect_handler="invenio_oauthclient.contrib.oidc:disconnect_rest_handler",
            signup_handler=dict(
                info="invenio_oauthclient.contrib.oidc:account_info",
                info_serializer="invenio_oauthclient.contrib.oidc:account_info_serializer",
                setup="invenio_oauthclient.contrib.oidc:account_setup",
                view="invenio_oauthclient.handlers.rest:signup_handler",
            ),
            response_handler="invenio_oauthclient.handlers.rest:default_remote_response_handler",
            authorized_redirect_url="/",
            disconnect_redirect_url="/",
            signup_redirect_url="/",
            error_redirect_url="/",
        )

    def get_handlers(self):
        """Return OIDC auth handlers."""
        return self._handlers

    def get_rest_handlers(self):
        """Return OIDC auth REST handlers."""
        return self._rest_handlers

    @property
    def userinfo_url(self):
        """Return the URL to fetch user info from OIDC discovery or fallback."""
        # Try to get from cached discovery document first
        if self._discovery_doc and "userinfo_endpoint" in self._discovery_doc:
            return self._discovery_doc["userinfo_endpoint"]

        # Fallback to manual construction
        endpoint_base = self._get_endpoint_base(self.issuer)
        return f"{endpoint_base.rstrip('/')}/userinfo"

    @property
    def discovery_url(self):
        """Return the OIDC discovery URL per RFC 8414.

        Per OIDC spec, the discovery URL is constructed as:
        {issuer}/.well-known/openid-configuration
        """
        return f"{self.issuer.rstrip('/')}/.well-known/openid-configuration"

    @property
    def jwks_url(self):
        """Return the JWKS (JSON Web Key Set) URL from OIDC discovery or fallback.

        Returns the jwks_uri from the discovery document if available,
        otherwise falls back to the standard OIDC path.
        """
        # Try to get from cached discovery document first
        if self._discovery_doc and "jwks_uri" in self._discovery_doc:
            return self._discovery_doc["jwks_uri"]

        # Fallback to manual construction
        return f"{self.issuer.rstrip('/')}/jwks"

    @property
    def logout_url(self):
        """Return the logout URL from OIDC discovery or fallback.

        Uses the full issuer path, including application name for Authentik.
        """
        # Try to get from cached discovery document first
        if self._discovery_doc and "end_session_endpoint" in self._discovery_doc:
            return self._discovery_doc["end_session_endpoint"]

        # Fallback to manual construction
        return f"{self.issuer.rstrip('/')}/logout"

    @staticmethod
    def _get_endpoint_base(issuer):
        """Get the endpoint base URL from issuer.

        For Authentik-style paths (/application/o/{app}/), returns the base path
        without the app name. For other issuers, returns the issuer unchanged.

        :param issuer: The issuer identifier.
        :returns: The endpoint base URL.
        """
        if "/application/o/" in issuer:
            parts = issuer.split("/application/o/")
            if len(parts) == 2:
                return f"{parts[0]}/application/o"
        return issuer

    @staticmethod
    def _fetch_oidc_discovery(issuer):
        """Fetch and cache OIDC discovery document.

        Implements OpenID Connect Discovery 1.0 (RFC 8414) for automatic
        endpoint configuration.

        Per OIDC spec, the discovery document is located at:
        {issuer}/.well-known/openid-configuration

        :param issuer: The issuer identifier (base_url + optional path).
        :returns: Dictionary containing the discovery document or None.
        """
        # Check cache first to avoid repeated network requests
        if issuer in _discovery_cache:
            return _discovery_cache[issuer]

        # Construct discovery URL per OIDC spec
        discovery_url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"

        try:
            response = requests.get(discovery_url, timeout=10)
            response.raise_for_status()
            discovery_doc = response.json()

            # Validate required OIDC discovery fields per RFC 8414
            required_fields = [
                "issuer",
                "authorization_endpoint",
                "token_endpoint",
                "userinfo_endpoint",
            ]

            if not all(field in discovery_doc for field in required_fields):
                raise ValueError(
                    f"Discovery document missing required fields: {required_fields}"
                )

            # Cache the discovery document using the issuer as key
            _discovery_cache[issuer] = discovery_doc
            return discovery_doc

        except (requests.RequestException, ValueError):
            # Return None to trigger fallback to manual configuration
            return None

    @staticmethod
    def _fetch_jwks(jwks_uri):
        """Fetch and cache JWKS (JSON Web Key Set) document.

        JWKS contains the public keys used to verify JWT signatures.
        This is essential for validating ID tokens in OIDC flows.

        :param jwks_uri: The URI of the JWKS endpoint.
        :returns: Dictionary containing the JWKS document or None.
        """
        # Check cache first to avoid repeated network requests
        if jwks_uri in _jwks_cache:
            return _jwks_cache[jwks_uri]

        try:
            response = requests.get(jwks_uri, timeout=10)
            response.raise_for_status()
            jwks_doc = response.json()

            # Validate JWKS structure - must contain 'keys' array
            if "keys" not in jwks_doc or not isinstance(jwks_doc["keys"], list):
                raise ValueError("JWKS document must contain 'keys' array")

            # Cache the JWKS document
            _jwks_cache[jwks_uri] = jwks_doc
            return jwks_doc

        except (requests.RequestException, ValueError) as e:
            try:
                current_app.logger.warning(
                    f"Failed to fetch JWKS from {jwks_uri}: {str(e)}"
                )
            except RuntimeError:
                # No app context available
                pass
            return None

    def get_jwks(self):
        """Get the JWKS (JSON Web Key Set) for this OIDC provider.

        Returns the cached JWKS or fetches it from the jwks_uri.

        :returns: Dictionary containing the JWKS document or None if unavailable.
        """
        jwks_uri = self.jwks_url
        if jwks_uri:
            return self._fetch_jwks(jwks_uri)
        return None


def _get_oidc_app():
    """Get or create OIDC app instance with runtime configuration.

    This function allows for lazy initialization to access current_app.config
    at runtime instead of module import time. It checks for OIDC_ISSUER
    in the following order:
    1. Flask app config (current_app.config)
    2. Environment variable (OIDC_ISSUER)
    3. Returns None if not configured (OIDC disabled)
    """
    try:
        issuer = current_app.config.get(
            "OIDC_ISSUER",
            os.environ.get("OIDC_ISSUER", None),
        )
    except RuntimeError:
        # No app context available, use environment variable
        issuer = os.environ.get("OIDC_ISSUER", None)

    if not issuer:
        # OIDC not configured, return None to disable
        return None

    try:
        use_basic_auth = current_app.config.get(
            "OIDC_USE_BASIC_AUTH",
            os.environ.get("OIDC_USE_BASIC_AUTH", "false").lower()
            in ("1", "true", "yes"),
        )
    except RuntimeError:
        use_basic_auth = os.environ.get("OIDC_USE_BASIC_AUTH", "").lower() in (
            "1",
            "true",
            "yes",
        )

    return OIDCSettingsHelper(issuer=issuer, use_basic_auth=use_basic_auth)


# Module-level helper functions for lazy-loaded configuration
def _get_base_app():
    """Get BASE_APP configuration with runtime config access."""
    app = _get_oidc_app()
    return app.base_app if app else None


def _get_remote_app():
    """Get REMOTE_APP configuration with runtime config access."""
    app = _get_oidc_app()
    return app.remote_app if app else None


def _get_remote_rest_app():
    """Get REMOTE_REST_APP configuration with runtime config access."""
    app = _get_oidc_app()
    return app.remote_rest_app if app else None


# Module-level lazy-loaded configuration using LocalProxy
# These proxies delay evaluation until accessed within an app context
BASE_APP = LocalProxy(_get_base_app)
"""OIDC base application configuration (lazy-loaded)."""

REMOTE_APP = LocalProxy(_get_remote_app)
"""OIDC remote application configuration (lazy-loaded)."""

REMOTE_REST_APP = LocalProxy(_get_remote_rest_app)
"""OIDC remote REST application configuration (lazy-loaded)."""


def get_user_info(remote):
    """Get user information from OIDC userinfo endpoint.

    Follows the OpenID Connect Core 1.0 specification for the userinfo endpoint.

    :param remote: The remote application.
    :returns: User information dictionary.
    :raises OAuthResponseError: If the request fails or response is invalid.
    """
    try:
        # Get issuer and construct OIDCSettingsHelper to access userinfo_url
        # which uses OIDC discovery when available
        app = _get_oidc_app()
        issuer = getattr(remote, "issuer", app.issuer)
        helper = OIDCSettingsHelper(issuer=issuer)
        response = remote.get(helper.userinfo_url)
        if getattr(response, "_resp", None) and response._resp.code >= 400:
            raise OAuthResponseError(
                _("Failed to fetch user information from OIDC provider"),
                None,
                response,
            )

        user_info = response.data

        # Validate required OIDC fields
        if "sub" not in user_info:
            raise OAuthResponseError(
                _("Missing subject identifier in user info"),
                None,
                response,
            )

        return user_info

    except Exception as e:
        if isinstance(e, OAuthResponseError):
            raise
        raise OAuthResponseError(
            _("Failed to fetch user information"), None, None
        ) from e


def _normalize_orcid(orcid):
    """Normalize an ORCID iD value.

    If the value is given as a URL (e.g. 'https://orcid.org/<id>'), it returns
    the bare ORCID iD.
    """
    if not orcid:
        return None

    if not isinstance(orcid, str):
        return orcid

    value = orcid.strip()
    for prefix in (
        "https://orcid.org/",
        "http://orcid.org/",
    ):
        if value.startswith(prefix):
            value = value[len(prefix) :]
            break

    value = value.lstrip("/").rstrip("/")
    return value or None


def account_info_serializer(remote, resp, user_info=None, **kwargs):
    """Serialize the account info response object.

    :param remote: The remote application.
    :param resp: The response of the `authorized` endpoint.
    :param user_info: User info from userinfo endpoint.
    :returns: A dictionary with serialized user information.
    """
    if not user_info:
        raise ValueError("User info is required for account serialization")

    # Extract external ID from 'sub' claim (standard OIDC)
    external_id = user_info.get("sub")
    if not external_id:
        raise ValueError("Subject identifier (sub) is required")

    # Extract email with fallback
    email = user_info.get("email")
    if not email:
        current_app.logger.warning(
            "No email provided by OIDC provider, using sub as fallback"
        )
        email = f"{external_id}@oidc.local"

    # Extract username with fallbacks
    username = (
        user_info.get("preferred_username")
        or user_info.get("nickname")
        or user_info.get("sub")
    )

    # Extract full name with fallback
    full_name = user_info.get("name", "")
    if not full_name and user_info.get("given_name"):
        full_name = " ".join(
            filter(
                None,
                [user_info.get("given_name"), user_info.get("family_name")],
            )
        )

    # Optional ORCID (if provided by the OIDC provider)
    orcid = _normalize_orcid(user_info.get("orcid"))

    # Optional picture (if provided by the OIDC provider)
    picture = user_info.get("picture")
    if isinstance(picture, str):
        picture = picture.strip() or None

    profile = {
        "username": username,
        "full_name": full_name,
    }
    if orcid:
        profile["orcid"] = orcid
    if picture:
        profile["picture"] = picture

    return {
        "external_id": external_id,
        "external_method": remote.name,
        "user": {
            "email": email,
            "profile": {
                **profile,
            },
        },
    }


def account_info(remote, resp):
    """Retrieve remote account information used to find local user.

    It returns a dictionary with the following structure:

    .. code-block:: python

        {
            'user': {
                'email': '...',
                'profile': {
                    'username': '...',
                    'full_name': '...',
                    # Optional: picture URL if provided by the OIDC provider
                    'picture': 'https://example.org/avatar.jpg',
                    # Optional: ORCID iD if provided by the OIDC provider
                    'orcid': '0000-0002-1825-0097',
                },
            },
            'external_id': 'oidc-sub-claim',
            'external_method': 'oidc',
        }

    :param remote: The remote application.
    :param resp: The response of the `authorized` endpoint.
    :returns: A dictionary with the user information.
    """
    try:
        user_info = get_user_info(remote)
        handlers = current_oauthclient.signup_handlers[remote.name]
        # `remote` param automatically injected via `make_handler` helper
        return handlers["info_serializer"](resp, user_info=user_info)

    except Exception as e:
        current_app.logger.error(f"Failed to get account info: {str(e)}")
        raise


def account_setup(remote, token, resp):
    """Perform additional setup after user has been logged in.

    :param remote: The remote application.
    :param token: The token value.
    :param resp: The response.
    """
    try:
        user_info = get_user_info(remote)
        current_app.logger.debug(f"User info retrieved: {user_info}")

        with db.session.begin_nested():
            # Store comprehensive user data in extra_data
            extra_data = {
                "sub": user_info.get("sub"),
                "email": user_info.get("email"),
                "full_name": user_info.get("name", ""),
                "username": (
                    user_info.get("preferred_username")
                    or user_info.get("nickname")
                    or ""
                ),
            }

            # Store optional fields if present
            optional_fields = [
                "given_name",
                "family_name",
                "nickname",
                "preferred_username",
                "groups",
                "picture",
            ]
            for field in optional_fields:
                if field in user_info:
                    extra_data[field] = user_info[field]

            # Optional ORCID (if provided by the OIDC provider)
            orcid = _normalize_orcid(user_info.get("orcid"))
            if orcid:
                extra_data["orcid"] = orcid

            # Store id_token for use as id_token_hint during RP-initiated logout
            id_token = resp.get("id_token") if resp else None
            if id_token:
                extra_data["id_token"] = id_token
                # Also keep in the session so post_logout() can use it after
                # logout_user() has cleared the user identity (but not the session).
                session["OAUTHCLIENT_OIDC_ID_TOKEN"] = id_token

            token.remote_account.extra_data = extra_data

            # Create user <-> external id link using 'sub' claim
            external_id = user_info.get("sub")
            if external_id:
                oauth_link_external_id(
                    token.remote_account.user,
                    dict(id=external_id, method=remote.name),
                )

            # Create user <-> external id link using optional ORCID iD.
            if orcid:
                oauth_link_external_id(
                    token.remote_account.user,
                    dict(id=orcid, method="orcid"),
                )

    except Exception as e:
        current_app.logger.error(f"Account setup failed: {str(e)}")
        db.session.rollback()
        raise


@require_more_than_one_external_account
def _disconnect(remote, *args, **kwargs):
    """Handle unlinking of remote account.

    :param remote: The remote application.
    """
    if not current_user.is_authenticated:
        return current_app.login_manager.unauthorized()

    account = RemoteAccount.get(
        user_id=current_user.get_id(), client_id=remote.consumer_key
    )

    if account and isinstance(account.extra_data, dict):
        with db.session.begin_nested():
            # Remove primary external ID link using stored sub claim
            external_id = account.extra_data.get("sub")
            if external_id:
                oauth_unlink_external_id(dict(id=external_id, method=remote.name))

            # Remove optional ORCID external ID link (if it was linked by this remote).
            orcid = account.extra_data.get("orcid")
            if orcid:
                oauth_unlink_external_id(dict(id=orcid, method="orcid"))

            account.delete()


def disconnect_handler(remote, *args, **kwargs):
    """Handle unlinking of remote account.

    :param remote: The remote application.
    :returns: The HTML response.
    """
    _disconnect(remote, *args, **kwargs)
    return redirect(url_for("invenio_oauthclient_settings.index"))


def disconnect_rest_handler(remote, *args, **kwargs):
    """Handle unlinking of remote account.

    :param remote: The remote application.
    :returns: The JSON response.
    """
    _disconnect(remote, *args, **kwargs)
    rconfig = current_app.config["OAUTHCLIENT_REST_REMOTE_APPS"][remote.name]
    redirect_url = rconfig["disconnect_redirect_url"]
    return response_handler(remote, redirect_url)
