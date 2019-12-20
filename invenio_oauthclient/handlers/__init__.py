# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2019 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Handlers for customizing oauthclient endpoints."""

from __future__ import absolute_import, print_function

from .ui import authorized_default_handler, authorized_signup_handler, \
    disconnect_handler, oauth2_handle_error, oauth_error_handler, \
    signup_handler
from .utils import authorized_handler, get_session_next_url, make_handler, \
    make_token_getter, oauth1_token_setter, oauth2_token_setter, \
    oauth_logout_handler, response_token_setter, set_session_next_url, \
    token_delete, token_getter, token_session_key, token_setter
