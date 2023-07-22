# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2019 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Handlers for customizing oauthclient endpoints."""

from flask_login import current_user
from invenio_db import db

from ..errors import OAuthClientUnAuthorized
from ..models import RemoteAccount
from .utils import require_more_than_one_external_account


@require_more_than_one_external_account
def base_disconnect_handler(remote, *args, **kwargs):
    """Handle unlinking of remote account.

    This default handler will just delete the remote account link. You may
    wish to extend this module to perform clean-up in the remote service
    before removing the link (e.g. removing install webhooks).

    :param remote: The remote application.
    :returns: Redirect response.
    """
    if not current_user.is_authenticated:
        raise OAuthClientUnAuthorized()

    with db.session.begin_nested():
        account = RemoteAccount.get(
            user_id=current_user.get_id(), client_id=remote.consumer_key
        )
        if account:
            account.delete()

    db.session.commit()
