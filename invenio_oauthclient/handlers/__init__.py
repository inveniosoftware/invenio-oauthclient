# SPDX-FileCopyrightText: 2015-2025 CERN.
# SPDX-License-Identifier: MIT

"""Handlers for customizing oauthclient endpoints."""

from .rest import authorized_default_handler as authorized_default_handler_rest
from .rest import authorized_signup_handler as authorized_signup_handler_rest
from .rest import disconnect_handler as disconnect_handler_rest
from .rest import signup_handler as signup_handler_rest
from .token import (
    get_session_next_url,
    make_token_getter,
    oauth1_token_setter,
    oauth2_token_setter,
    oauth_logout_handler,
    response_token_setter,
    set_session_next_url,
    token_delete,
    token_getter,
    token_session_key,
    token_setter,
)
from .ui import (
    authorized_default_handler,
    authorized_signup_handler,
    disconnect_handler,
    oauth2_handle_error,
    oauth_resp_remote_error_handler,
    signup_handler,
)
from .utils import authorized_handler, make_handler

# settle the disagreement between isort and black by renaming here
oauth_error_handler = oauth_resp_remote_error_handler

__all__ = (
    "authorized_default_handler_rest",
    "authorized_default_handler",
    "authorized_handler",
    "authorized_signup_handler_rest",
    "authorized_signup_handler",
    "disconnect_handler_rest",
    "disconnect_handler",
    "get_session_next_url",
    "make_handler",
    "make_token_getter",
    "oauth_error_handler",
    "oauth_logout_handler",
    "oauth1_token_setter",
    "oauth2_handle_error",
    "oauth2_token_setter",
    "response_token_setter",
    "set_session_next_url",
    "signup_handler_rest",
    "signup_handler",
    "token_delete",
    "token_getter",
    "token_session_key",
    "token_setter",
)
