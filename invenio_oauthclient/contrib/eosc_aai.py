# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2025 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Pre-configured remote application for enabling sign in/up with EOSC AAI.

1. Edit your configuration and add:

   .. code-block:: python

       from invenio_oauthclient.contrib import eosc_aai

       OAUTHCLIENT_REMOTE_APPS = dict(
           eosc_aai=eosc_aai.REMOTE_APP,
       )

       EOSC_AAI_APP_CREDENTIALS = dict(
           consumer_key="changeme",
           consumer_secret="changeme",
       )

  Note, if you want to use other environments:
  - For testing: ``eosc_aai.REMOTE_TESTING_APP``
  - For staging: ``eosc_aai.REMOTE_STAGING_APP``
  - For production: ``eosc_aai.REMOTE_APP`` (default)

2. Register a new application with EOSC AAI. Visit the appropriate Service
   Registration URL for your environment:

   - Testing: https://webapp.testing.eosc-federation.eu/sp_request
   - Staging: https://webapp.staging.eosc-federation.eu/sp_request
   - Production: https://webapp.aai.open-science-cloud.ec.europa.eu/sp_request

   When registering ensure that the *Redirect URI* points to:
   ``CFG_SITE_URL/oauth/authorized/eosc_aai/`` (e.g.
   ``https://localhost:5000/oauth/authorized/eosc_aai/``).

3. Grab the *Client ID* and *Client Secret* after registering the application
   and add them to your instance configuration (``invenio.cfg``):

   .. code-block:: python

       EOSC_AAI_APP_CREDENTIALS = dict(
           consumer_key="<CLIENT ID>",
           consumer_secret="<CLIENT SECRET>",
       )

4. Now go to ``CFG_SITE_URL/oauth/login/eosc_aai/`` (e.g.
   http://localhost:4000/oauth/login/eosc_aai/)

5. Also, you should see EOSC AAI listed under Linked accounts:
   http://localhost:4000/account/settings/linkedaccounts/

By default the EOSC AAI module will try first look if a link already exists
between a EOSC AAI account and a user. If no link is found, the user is asked
to provide an email address to sign-up.

In templates you can add a sign in/up link:

.. code-block:: jinja

    <a href="{{url_for('invenio_oauthclient.login', remote_app='eosc_aai')}}">
      Sign in with EOSC AAI
    </a>

"""

import base64
import hashlib
import secrets

from flask import current_app, redirect, session, url_for
from flask_login import current_user
from flask_oauthlib.client import OAuthRemoteApp
from invenio_db import db
from invenio_i18n import lazy_gettext as _

from invenio_oauthclient import current_oauthclient
from invenio_oauthclient.contrib.settings import OAuthSettingsHelper
from invenio_oauthclient.handlers.rest import response_handler
from invenio_oauthclient.handlers.utils import require_more_than_one_external_account
from invenio_oauthclient.models import RemoteAccount
from invenio_oauthclient.oauth import oauth_link_external_id, oauth_unlink_external_id


class EOSCAAIOAuthRemoteApp(OAuthRemoteApp):
    """Custom OAuth remote app with PKCE support for EOSC AAI."""

    def authorize(self, callback=None, **kwargs):
        """Override authorize method to add PKCE parameters."""
        # Generate code verifier (43-128 characters, URL-safe)
        code_verifier = (
            base64.urlsafe_b64encode(secrets.token_bytes(32))
            .decode("utf-8")
            .rstrip("=")
        )

        # Generate code challenge using SHA256
        code_challenge = (
            base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode("utf-8")).digest()
            )
            .decode("utf-8")
            .rstrip("=")
        )

        # Store code verifier in session for later use in token exchange
        session[f"oauth_code_verifier_{self.name}"] = code_verifier

        # Add PKCE parameters to the authorization request
        kwargs.update(
            {"code_challenge": code_challenge, "code_challenge_method": "S256"}
        )

        return super().authorize(callback=callback, **kwargs)

    def handle_oauth2_response(self, args):
        """Override token exchange to include PKCE code_verifier."""
        # Get the stored code_verifier from session
        code_verifier = session.pop(f"oauth_code_verifier_{self.name}", None)

        if code_verifier:
            # Add code_verifier to access_token_params for token exchange
            if not hasattr(self, "access_token_params"):
                self.access_token_params = {}
            self.access_token_params["code_verifier"] = code_verifier

        # Call the parent implementation to perform token exchange
        return super().handle_oauth2_response(args)


class EOSCAAIOAuthSettingsHelper(OAuthSettingsHelper):
    """Default configuration for EOSC AAI OAuth provider."""

    def __init__(
        self,
        title=None,
        description=None,
        base_url=None,
        app_key=None,
        precedence_mask=None,
        signup_options=None,
    ):
        """Constructor."""
        precedence_mask = precedence_mask or {
            "email": False,
        }
        signup_options = signup_options or {
            "auto_confirm": False,
            "send_register_msg": True,
        }

        super().__init__(
            title or _("EOSC AAI"),
            description
            or _(
                "European Open Science Cloud Authentication and Authorization Infrastructure."
            ),
            base_url=base_url,
            app_key=app_key or "EOSC_AAI_APP_CREDENTIALS",
            request_token_params={
                "scope": "openid profile email entitlements",
            },
            access_token_url=f"{base_url}/OIDC/token",
            authorize_url=f"{base_url}/OIDC/authorization",
            content_type="application/json",
            precedence_mask=precedence_mask,
            signup_options=signup_options,
        )

        # Override the base_app to use our custom remote app class with PKCE support
        self.base_app["remote_app"] = (
            "invenio_oauthclient.contrib.eosc_aai:EOSCAAIOAuthRemoteApp"
        )

        self._handlers = dict(
            authorized_handler="invenio_oauthclient.handlers:authorized_signup_handler",
            disconnect_handler="invenio_oauthclient.contrib.eosc_aai:disconnect_handler",
            signup_handler=dict(
                info="invenio_oauthclient.contrib.eosc_aai:account_info",
                info_serializer="invenio_oauthclient.contrib.eosc_aai:account_info_serializer",
                setup="invenio_oauthclient.contrib.eosc_aai:account_setup",
                view="invenio_oauthclient.handlers:signup_handler",
            ),
        )

        self._rest_handlers = dict(
            authorized_handler="invenio_oauthclient.handlers.rest:authorized_signup_handler",
            disconnect_handler="invenio_oauthclient.contrib.eosc_aai:disconnect_rest_handler",
            signup_handler=dict(
                info="invenio_oauthclient.contrib.eosc_aai:account_info",
                info_serializer="invenio_oauthclient.contrib.eosc_aai:account_info_serializer",
                setup="invenio_oauthclient.contrib.eosc_aai:account_setup",
                view="invenio_oauthclient.handlers.rest:signup_handler",
            ),
            response_handler="invenio_oauthclient.handlers.rest:default_remote_response_handler",
            authorized_redirect_url="/",
            disconnect_redirect_url="/",
            signup_redirect_url="/",
            error_redirect_url="/",
        )

    def get_handlers(self):
        """Return EOSC AAI auth handlers."""
        return self._handlers

    def get_rest_handlers(self):
        """Return EOSC AAI auth REST handlers."""
        return self._rest_handlers


# Production environment (default)
_eosc_aai_app = EOSCAAIOAuthSettingsHelper(
    base_url="https://proxy.aai.open-science-cloud.ec.europa.eu",
)

BASE_APP = _eosc_aai_app.base_app
REMOTE_APP = _eosc_aai_app.remote_app
"""EOSC AAI Production Remote Application."""

REMOTE_REST_APP = _eosc_aai_app.remote_rest_app
"""EOSC AAI Production Remote REST Application."""


# Testing environment
_eosc_aai_testing_app = EOSCAAIOAuthSettingsHelper(
    base_url="https://proxy.testing.eosc-federation.eu",
)
REMOTE_TESTING_APP = _eosc_aai_testing_app.remote_app
"""EOSC AAI Testing Remote Application."""

REMOTE_TESTING_REST_APP = _eosc_aai_testing_app.remote_rest_app
"""EOSC AAI Testing Remote REST Application."""


# Staging environment
_eosc_aai_staging_app = EOSCAAIOAuthSettingsHelper(
    base_url="https://proxy.staging.eosc-federation.eu",
)
REMOTE_STAGING_APP = _eosc_aai_staging_app.remote_app
"""EOSC AAI Staging Remote Application."""

REMOTE_STAGING_REST_APP = _eosc_aai_staging_app.remote_rest_app
"""EOSC AAI Staging Remote REST Application."""


def account_info_serializer(remote, resp, **kwargs):
    """Serialize the account info response object.

    :param remote: The remote application.
    :param resp: The response of the `authorized` endpoint.
    :returns: A dictionary with serialized user information.
    """
    return {
        "external_id": resp.get("sub"),
        "external_method": remote.name,
        "user": {
            "email": resp.get("email"),
            "profile": {
                "full_name": resp.get("name"),
                "given_name": resp.get("given_name"),
                "family_name": resp.get("family_name"),
            },
        },
        "active": True,
    }


def account_info(remote, resp):
    """Retrieve remote account information used to find local user.

    It returns a dictionary with the following structure:

    .. code-block:: python

        {
            'user': {
                'email': 'user@example.org',
                'profile': {
                    'full_name': 'Full Name',
                    'given_name': 'First',
                    'family_name': 'Last',
                },
            },
            'external_id': 'eosc-aai-user-identifier',
            'external_method': 'eosc_aai',
            'active': True,
        }

    :param remote: The remote application.
    :param resp: The response of the `authorized` endpoint.
    :returns: A dictionary with the user information.
    """
    handlers = current_oauthclient.signup_handlers[remote.name]
    # `remote` param automatically injected via `make_handler` helper
    return handlers["info_serializer"](resp)


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
    eosc_sub = account.extra_data.get("sub") if account else None

    if eosc_sub:
        oauth_unlink_external_id({"id": eosc_sub, "method": "eosc_aai"})
    if account:
        with db.session.begin_nested():
            account.delete()


def disconnect_handler(remote, *args, **kwargs):
    """Handle unlinking of remote account.

    :param remote: The remote application.
    """
    _disconnect(remote, *args, **kwargs)
    return redirect(url_for("invenio_oauthclient_settings.index"))


def disconnect_rest_handler(remote, *args, **kwargs):
    """Handle unlinking of remote account.

    :param remote: The remote application.
    """
    _disconnect(remote, *args, **kwargs)
    redirect_url = current_app.config["OAUTHCLIENT_REST_REMOTE_APPS"][remote.name][
        "disconnect_redirect_url"
    ]
    return response_handler(remote, redirect_url)


def account_setup(remote, token, resp):
    """Perform additional setup after user have been logged in.

    :param remote: The remote application.
    :param token: The token value.
    :param resp: The response.
    """
    with db.session.begin_nested():
        # Retrieve EOSC AAI data from response
        sub = resp.get("sub")
        full_name = resp.get("name")
        given_name = resp.get("given_name")
        family_name = resp.get("family_name")
        email = resp.get("email")
        eunode_projects = resp.get("eunode_projects", [])
        entitlements = resp.get("entitlements", [])

        # Set EOSC AAI data in extra_data
        token.remote_account.extra_data = {
            "sub": sub,
            "full_name": full_name,
            "given_name": given_name,
            "family_name": family_name,
            "email": email,
            "eunode_projects": eunode_projects,
            "entitlements": entitlements,
        }

        user = token.remote_account.user

        # Create user <-> external id link
        oauth_link_external_id(user, {"id": sub, "method": "eosc_aai"})
