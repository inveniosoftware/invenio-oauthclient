# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2021 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Pre-configured remote application for enabling sign in/up with OpenAIRE.

1. Edit your configuration and add:

   .. code-block:: python

       from invenio_oauthclient.contrib import openaire_aai

       OAUTHCLIENT_REMOTE_APPS = dict(
           openaire_aai=openaire_aai.REMOTE_APP,
       )

       OPENAIRE_APP_CREDENTIALS = dict(
           consumer_key="changeme",
           consumer_secret="changeme",
       )

  In case you want use sandbox ``openaire_aai.REMOTE_SANDBOX_APP`` instead
  of ``openaire_aai.REMOTE_APP``.

2. Register a new application with OpenAIRE, by sending an email to
   <aai@openaire.eu>, with the following information:

   - Client ID for your application (e.g. ``my-app``).
   - One or more *Redirect URI*s pointing to
    ``https://<host>/oauth/authorized/openaire_aai/`` (e.g.
    ``https://localhost:5000/oauth/authorized/openaire_aai/``).
   - User claim scopes ``openid profile email orcid``.
   - One or more of the OpenID Connect/OAuth2 grant types: Authorization Code,
    Token Exchange, Device Code.

3. Once you have your *Client ID* and *Client Secret* add them to your instance
   configuration (e.g. ``invenio.cfg``):

   .. code-block:: python

        OPENAIRE_APP_CREDENTIALS = dict(
           consumer_key="<CLIENT ID>",
           consumer_secret="<CLIENT SECRET>",
        )

4. Now go to ``https://<host>/oauth/login/openaire_aai/`` (e.g.
   https://localhost:5000/oauth/login/openaire_aai/)

5. Also, you should see OpenAIRE listed under Linked accounts:
   https://localhost:5000/account/settings/linkedaccounts/

By default the OpenAIRE module will try first look if a link already exists
between a OpenAIRE account and a user. If no link is found, the user is asked
to provide an email address to sign-up.

In templates you can add a sign in/up link:

.. code-block:: jinja

    <a href="{{url_for('invenio_oauthclient.login',
        remote_app='openaire_aai')}}">
      Sign in with OpenAIRE
    </a>

"""

import jwt
from flask import current_app, redirect, url_for
from flask_login import current_user
from invenio_db import db

from invenio_oauthclient import current_oauthclient
from invenio_oauthclient.contrib.settings import OAuthSettingsHelper
from invenio_oauthclient.handlers.rest import response_handler
from invenio_oauthclient.handlers.utils import require_more_than_one_external_account
from invenio_oauthclient.models import RemoteAccount
from invenio_oauthclient.utils import oauth_link_external_id, oauth_unlink_external_id


class OpenAIREAuthSettingsHelper(OAuthSettingsHelper):
    """Default configuration for OpenAIRE OAuth provider."""

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
        base_url = base_url or "https://aai.openaire.eu"
        super().__init__(
            title or "OpenAIRE",
            description or "Open Science Services.",
            base_url,
            app_key or "OPENAIRE_APP_CREDENTIALS",
            request_token_params={"scope": "openid profile email orcid"},
            access_token_url=f"{base_url}/oidc/token",
            authorize_url=f"{base_url}/oidc/authorize",
            content_type="application/json",
            precedence_mask=precedence_mask or {"email": True},
            signup_options=signup_options,
        )

        self._handlers = dict(
            authorized_handler="invenio_oauthclient.handlers:authorized_signup_handler",
            disconnect_handler="invenio_oauthclient.contrib.openaire_aai:disconnect_handler",
            signup_handler=dict(
                info="invenio_oauthclient.contrib.openaire_aai:account_info",
                info_serializer="invenio_oauthclient.contrib.openaire_aai:account_info_serializer",
                setup="invenio_oauthclient.contrib.openaire_aai:account_setup",
                view="invenio_oauthclient.handlers:signup_handler",
            ),
        )

        self._rest_handlers = dict(
            authorized_handler="invenio_oauthclient.handlers.rest:authorized_signup_handler",
            disconnect_handler="invenio_oauthclient.contrib.openaire_aai:disconnect_rest_handler",
            signup_handler=dict(
                info="invenio_oauthclient.contrib.openaire_aai:account_info",
                info_serializer="invenio_oauthclient.contrib.openaire_aai:account_info_serializer",
                setup="invenio_oauthclient.contrib.openaire_aai:account_setup",
                view="invenio_oauthclient.handlers.rest:signup_handler",
            ),
            response_handler="invenio_oauthclient.handlers.rest:default_remote_response_handler",
            authorized_redirect_url="/",
            disconnect_redirect_url="/",
            signup_redirect_url="/",
            error_redirect_url="/",
        )

    @property
    def user_info_url(self):
        """User info URL."""
        return f"{self.base_url}/oidc/userinfo"

    def get_handlers(self):
        """Return OpenAIRE auth handlers."""
        return self._handlers

    def get_rest_handlers(self):
        """Return OpenAIRE auth REST handlers."""
        return self._rest_handlers


# Production
_openaire_aai_app = OpenAIREAuthSettingsHelper()

BASE_APP = _openaire_aai_app.base_app
REMOTE_APP = _openaire_aai_app.remote_app
"""OpenAIRE Remote Application."""

REMOTE_REST_APP = _openaire_aai_app.remote_rest_app
"""OpenAIRE Remote REST Application."""

# Sandbox
_openaire_aai_sandbox_app = OpenAIREAuthSettingsHelper(
    base_url="https://openaire-dev.aai-dev.grnet.gr",
)
REMOTE_SANDBOX_APP = _openaire_aai_sandbox_app.remote_app
"""OpenAIRE Sandbox Remote Application."""

REMOTE_SANDBOX_REST_APP = _openaire_aai_sandbox_app.remote_rest_app
"""OpenAIRE Sandbox Remote REST Application."""

OAUTHCLIENT_OPENAIRE_AAI_JWT_DECODE_PARAMS = dict(
    options=dict(
        verify_signature=False,
        verify_aud=False,
    ),
    algorithms=[
        "HS256",
        "HS384",
        "HS512",
        "RS256",
        "RS384",
        "RS512",
        "ES256",
        "ES384",
        "ES512",
        "PS256",
        "PS384",
        "PS512",
    ],
)
"""OpenAIRE AAI JWT decoding parameters."""


def account_info_serializer(remote, resp, user_info, **kwargs):
    """Serialize the account info response object.

    :param remote: The remote application.
    :param resp: The response of the `authorized` endpoint.
    :param user_info: The response of the `user info` endpoint.
    :returns: A dictionary with serialized user information.
    """
    return {
        "external_id": user_info["sub"],
        "external_method": remote.name,
        "user": {
            "profile": {
                "full_name": user_info.get("name"),
            },
            "email": user_info.get("email"),
        },
    }


def account_info(remote, resp):
    """Retrieve remote account information used to find local user.

    It returns a dictionary with the following structure:

    .. code-block:: python

        {
            'user': {
                'profile': {
                    'full_name': 'Full Name',
                },
                'email': '<openaire-email>',
            },
            'external_id': '<openaire-unique-identifier>',
            'external_method': 'openaire_aai',
        }

    :param remote: The remote application.
    :param resp: The response of the `authorized` endpoint.
    :returns: A dictionary with the user information.
    """
    user_info_url = f"{remote.base_url}/oidc/userinfo"
    user_info = remote.get(user_info_url).data

    handlers = current_oauthclient.signup_handlers[remote.name]
    # `remote` param automatically injected via `make_handler` helper
    return handlers["info_serializer"](resp, user_info)


@require_more_than_one_external_account
def _disconnect(remote, *args, **kwargs):
    """Handle unlinking of remote account.

    :param remote: The remote application.
    """
    if not current_user.is_authenticated:
        return current_app.login_manager.unauthorized()

    remote_account = RemoteAccount.get(
        user_id=current_user.get_id(), client_id=remote.consumer_key
    )
    external_ids = [
        i.id for i in current_user.external_identifiers if i.method == remote.name
    ]

    if external_ids:
        oauth_unlink_external_id(dict(id=external_ids[0], method=remote.name))
    if remote_account:
        with db.session.begin_nested():
            remote_account.delete()


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
    user_info = jwt.decode(
        resp["id_token"],
        **current_app.config.get(
            "OAUTHCLIENT_OPENAIRE_AAI_JWT_DECODE_PARAMS",
            OAUTHCLIENT_OPENAIRE_AAI_JWT_DECODE_PARAMS,
        ),
    )
    openaire_id = user_info["sub"]
    with db.session.begin_nested():
        user = token.remote_account.user

        # Set extra data so that we mark that the setup is done.
        token.remote_account.extra_data = {"id": openaire_id}

        # Create user <-> external id link.
        oauth_link_external_id(
            user,
            {"id": openaire_id, "method": remote.name},
        )
