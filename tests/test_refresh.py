# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2024 CESNET z.s.p.o.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Test handlers."""
import json
from datetime import datetime

from helpers import mock_remote_http_request

from invenio_oauthclient.models import RemoteToken


def test_refresh(models_fixture, app):
    """Test token getter on response from OAuth server."""
    datastore = app.extensions["invenio-accounts"].datastore
    existing_email = "existing@inveniosoftware.org"
    user = datastore.find_user(email=existing_email)

    rt = RemoteToken.create(
        user.id,
        "cern_key_changeme",
        "mytoken",
        "mysecret",
        refresh_token="myrefreshtoken",
        expires_at=datetime.utcnow(),
    )
    assert rt.is_expired is True

    ioc = app.extensions["oauthlib.client"]
    mock_remote_http_request(
        ioc,
        "cern_openid",
        [
            None,
            json.dumps(
                {
                    "access_token": "newtoken",
                    "token_type": "bearer",
                    "expires_in": 1199,
                    "refresh_token": "newrefreshtoken",
                }
            ),
        ],
    )

    rt.refresh_access_token()
    assert rt.is_expired is False
    assert rt.access_token == "newtoken"
    assert rt.refresh_token == "newrefreshtoken"
