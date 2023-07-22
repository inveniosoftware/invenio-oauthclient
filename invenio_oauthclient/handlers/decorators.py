# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2023 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Decorators."""

from functools import wraps

from flask import session
from flask_login import current_user

from ..errors import (
    OAuthClientAlreadyAuthorized,
    OAuthClientMustRedirectLogin,
    OAuthClientTokenNotFound,
)
from .token import token_getter, token_session_key


def can_extra_signup(f):
    """Ensure that the extra signup handler can be called.

    The handler can be called when the user is not yet authenticated
    and when the OAuth token is valid.
    """

    @wraps(f)
    def wrapper(*args, **kwargs):
        # make sure the user is not already authenticated
        if current_user.is_authenticated:
            raise OAuthClientAlreadyAuthorized()

        remote = args[0]
        # Make sure that there is an OAuth token in the session, to ensure that
        # we are in the OAuth flow
        oauth_token = token_getter(remote)
        if not oauth_token:
            raise OAuthClientTokenNotFound()

        # Make sure that `authorized` step executed first, and that the extra signup
        # step is actually needed because some user info is missing
        session_prefix = token_session_key(remote.name)
        if not session.get(session_prefix + "_autoregister", False):
            raise OAuthClientMustRedirectLogin()

        return f(*args, **kwargs)

    return wrapper
