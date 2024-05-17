# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2024 CESNET z.s.p.o.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Handler for refreshing access token."""

from flask_oauthlib.client import OAuthResponse
from flask_oauthlib.utils import to_bytes

from invenio_oauthclient.handlers.token import make_expiration_time

from ..models import RemoteToken
from ..proxies import current_oauthclient


def refresh_access_token(token: RemoteToken):
    """
    Internal method to refresh the access token.

    :param token: the remote token to be refreshed
    :returns tuple of (access_token, secret, refresh_token, expires_at)

    Note: the current access/refresh token are invalidated during this call
    """
    remote_account = token.remote_account
    client_id = remote_account.client_id
    remote = next(
        x
        for x in current_oauthclient.oauth.remote_apps.values()
        if x.consumer_key == client_id
    )
    client = remote.make_client()
    refresh_token_request = client.prepare_refresh_token_request(
        remote.access_token_url,
        refresh_token=token.refresh_token,
        client_id=remote.consumer_key,
        client_secret=remote.consumer_secret,
    )
    resp, content = remote.http_request(
        refresh_token_request[0],
        refresh_token_request[1],
        data=to_bytes(refresh_token_request[2], remote.encoding),
        method="POST",
    )
    resp = OAuthResponse(resp, content, remote.content_type)
    return (
        resp.data.get("access_token"),
        "",
        resp.data.get("refresh_token"),
        make_expiration_time(resp.data.get("expires_in")),
    )
