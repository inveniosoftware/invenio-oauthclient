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
        raise OAuthError(
            f"Invalid app name {app_name}. "
            "It should only contain letters, numbers, dashes "
            "and underscores",
            remote,
        )
    return f"OAUTHCLIENT_{app_name.upper()}"


def _format_public_key(public_key):
    """PEM-format the public key."""
    public_key = public_key.strip()

    if not public_key.startswith("-----BEGIN PUBLIC KEY-----"):
        public_key = (
            "-----BEGIN PUBLIC KEY-----\n" + public_key + "\n-----END PUBLIC KEY-----"
        )

    return public_key


def get_public_key(remote, realm_url):
    """Get the realm's public key with the ID kid from Keycloak."""
    certs_resp = remote.get(realm_url).data
    return certs_resp["public_key"]


def _get_user_info_from_token(remote, token, config_prefix):
    """Get the user information from the JWT token."""
    # try to parse the "id_token" part of Keycloak's (JWT) response
    realm_url = current_app.config[f"{config_prefix}_REALM_URL"]
    pubkey = _format_public_key(get_public_key(remote, realm_url))
    alg = jwt.get_unverified_header(token)["alg"]

    should_verify_aud = current_app.config.get(f"{config_prefix}_VERIFY_AUD", False)
    expected_aud = current_app.config.get(f"{config_prefix}_AUD", None)

    should_verify_expiration = current_app.config.get(
        f"{config_prefix}_VERIFY_EXP", False
    )

    options = {
        # check signature expiration
        "verify_exp": should_verify_expiration,
        # check the target audience
        "verify_aud": should_verify_aud and (expected_aud is not None),
    }

    return jwt.decode(
        token, key=pubkey, algorithms=[alg], audience=expected_aud, options=options
    )


def _get_user_info_from_endpoint(remote, config_prefix):
    """Get the user info from the oauth server provider."""
    url = current_app.config[f"{config_prefix}_USER_INFO_URL"]
    return remote.get(url).data


def get_user_info(remote, resp_token, from_token_only=False):
    """Get the user information from Keycloak.

    :param remote: The OAuthClient remote app
    :param resp_token: The response from the 'token' endpoint; expected to be a dict
        and to contain a JWT 'id_token'
    :param from_token_only: return info only from the token, without calling the
        user info endpoint.
    :returns: A tuple containing the user information extracted from the token, and
        if configured, from the UserInfo endpoint
    """
    config_prefix = _generate_config_prefix(remote)
    from_token, from_endpoint = {}, None

    try:
        from_token = _get_user_info_from_token(
            remote, resp_token["id_token"], config_prefix
        )
    except Exception as e:
        current_app.logger.exception(e)

    call_endpoint = current_app.config[f"{config_prefix}_USER_INFO_FROM_ENDPOINT"]
    if not from_token_only and call_endpoint:
        from_endpoint = _get_user_info_from_endpoint(remote, config_prefix)

    return from_token, from_endpoint
