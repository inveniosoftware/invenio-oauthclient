# -*- coding: utf-8 -*-
#
# Copyright (C) 2020 FAIR Data Austria.
#
# Invenio-Keycloak is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Helper functions for the endpoint handlers."""

import jwt
from flask import current_app


def _get_config_item(item):
    return current_app.config.get(item) or \
        current_app.config.get("OAUTHCLIENT_" + item)


def _get_user_info_url():
    """Get URL for the Keycloak userinfo endpoint from `app.config`."""
    return _get_config_item("KEYCLOAK_USER_INFO_URL")


def _get_realm_url():
    """Get URL for the Keycloak realm from `app.config`."""
    return _get_config_item("KEYCLOAK_REALM_URL")


def _get_aud():
    """Get the target audience ('aud' field) for Keycloak's JWT."""
    return _get_config_item("KEYCLOAK_AUD")


def _get_verify_aud():
    """Get the boolean flag whether or not to check 'aud' in JWT."""
    return _get_config_item("KEYCLOAK_VERIFY_AUD")


def _format_public_key(public_key):
    """PEM-format the public key."""
    public_key = public_key.strip()

    if not public_key.startswith("-----BEGIN PUBLIC KEY-----"):
        public_key = "-----BEGIN PUBLIC KEY-----\n" + \
                     public_key + \
                     "\n-----END PUBLIC KEY-----"

    return public_key


def get_public_key(remote):
    """Get the realm's public key with the ID kid from Keycloak."""
    certs_resp = remote.get(_get_realm_url()).data
    key = certs_resp["public_key"]

    return key


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
    try:
        # try to parse the "id_token" part of Keycloak's (JWT) response
        token = resp_token["id_token"]
        pubkey = _format_public_key(get_public_key(remote))
        alg = jwt.get_unverified_header(token)["alg"]

        if not isinstance(options, dict):
            options = {}

        # consult the config whether to check the target audience
        options.update({"verify_aud": False})
        aud = _get_aud()
        if _get_verify_aud() and (aud is not None):
            options.update({"verify_aud": True})

        user_info = jwt.decode(token,
                               key=pubkey,
                               algorithms=[alg],
                               audience=aud,
                               options=options)

    except:
        if not fallback_to_endpoint:
            raise

        # as a fallback, we can still contact Keycloak's userinfo endpoint
        # `remote.get(...)` automatically includes OAuth2 tokens in the header
        # and the response's `data` field is a dict
        user_info = remote.get(_get_user_info_url()).data

    return user_info
