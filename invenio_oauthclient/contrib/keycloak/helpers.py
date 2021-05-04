# -*- coding: utf-8 -*-
#
# Copyright (C) 2020-2021 TU Wien.
#
# Invenio-Keycloak is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Helper functions for the endpoint handlers."""

import re

import jwt
from flask import current_app

from ...errors import OAuthError, OAuthKeycloakUserInfoError

AZ_09_DASHES_UNDERSCORES = r"^[A-Za-z0-9_-]+$"


def is_app_name_valid(app_name):
    """Validate app name."""
    return re.match(AZ_09_DASHES_UNDERSCORES, app_name) is not None


def _generate_config_prefix(remote):
    """Validate the app name so that it can be used in config vars."""
    app_name = remote.name
    if not is_app_name_valid(app_name):
        raise OAuthError(f"Invalid app name {app_name}. "
                         "It should only contain letters, numbers, dashes "
                         "and underscores", remote)
    return f"OAUTHCLIENT_{app_name.upper()}"


def _format_public_key(public_key):
    """PEM-format the public key."""
    public_key = public_key.strip()

    if not public_key.startswith("-----BEGIN PUBLIC KEY-----"):
        public_key = "-----BEGIN PUBLIC KEY-----\n" + \
                     public_key + \
                     "\n-----END PUBLIC KEY-----"

    return public_key


def get_public_key(remote, realm_url):
    """Get the realm's public key with the ID kid from Keycloak."""
    certs_resp = remote.get(realm_url).data
    return certs_resp["public_key"]


def get_user_info(remote, resp_token,
                  fallback_to_endpoint=True,
                  options=dict()):
    """Get the user information from Keycloak.

    :param remote: The OAuthClient remote app
    :param resp: The response from the 'token' endpoint; expected to be a dict
        and to contain a JWT 'id_token'
    :param fallback_to_endpoint: Whether or not to fall back to the 'userinfo'
        endpoint mechanism when verifying the 'id_token' fails
    :param options: A dictionary with additional options for `jwt.decode`
    """
    config_prefix = _generate_config_prefix(remote)
    try:
        # try to parse the "id_token" part of Keycloak's (JWT) response
        token = resp_token["id_token"]
        realm_url = current_app.config[f"{config_prefix}_REALM_URL"]
        pubkey = _format_public_key(get_public_key(remote, realm_url))
        alg = jwt.get_unverified_header(token)["alg"]

        if not isinstance(options, dict):
            options = {}

        # consult the config whether to check the target audience
        should_verify_aud = current_app.config.get(
            f"{config_prefix}_VERIFY_AUD",
            False
        )
        expected_aud = current_app.config.get(
            f"{config_prefix}_AUD",
            None
        )

        if should_verify_aud and (expected_aud is not None):
            options.update({"verify_aud": True})
        else:
            options.update({"verify_aud": False})

        # consult the config whether to check signature expiration
        should_verify_expiration = current_app.config.get(
            f"{config_prefix}_VERIFY_EXP",
            False
        )

        if should_verify_expiration:
            options.update({"verify_exp": True})
        else:
            options.update({"verify_exp": False})

        user_info = jwt.decode(token,
                               key=pubkey,
                               algorithms=[alg],
                               audience=expected_aud,
                               options=options)

    except Exception as e:
        if not fallback_to_endpoint:
            raise OAuthKeycloakUserInfoError(
                "Error while fetching user information: {}".format(e),
                remote,
                resp_token
            )

        # as a fallback, we can still contact Keycloak's userinfo endpoint
        # `remote.get(...)` automatically includes OAuth2 tokens in the header
        # and the response's `data` field is a dict
        url = current_app.config[f"{config_prefix}_USER_INFO_URL"]
        user_info = remote.get(url).data

    return user_info
