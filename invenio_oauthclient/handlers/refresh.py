# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2024 CESNET z.s.p.o.
# Copyright (C) 2025 CERN.
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
    Internal method to refresh the access token (via RFC 6749 Section 6).

    :param token: the remote token to be refreshed
    :returns tuple of (access_token, refresh_token, expires)

    Note: the current access/refresh token are invalidated during this call
    """
    remote_account = token.remote_account
    client_id = remote_account.client_id
    # Find the remote by client ID
    remote = next(
        x
        for x in current_oauthclient.oauth.remote_apps.values()
        if x.consumer_key == client_id
    )
    client = remote.make_client()
    request_url, request_headers, request_body = client.prepare_refresh_token_request(
        remote.access_token_url,
        refresh_token=token.refresh_token,
        client_id=remote.consumer_key,
        client_secret=remote.consumer_secret,
    )
    resp, content = remote.http_request(
        request_url,
        request_headers,
        data=to_bytes(request_body, remote.encoding),
        method="POST",
    )
    resp = OAuthResponse(resp, content, remote.content_type)
    return (
        resp.data.get("access_token"),
        # As per the RFC, the server MAY issue a new refresh token of an identical scope, which we must save.
        resp.data.get("refresh_token"),
        make_expiration_time(resp.data.get("expires_in")),
    )
