# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2025 CERN.
# Copyright (C) 2024 Graz University of Technology.
# Copyright (C) 2025 KTH Royal Institute of Technology.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Advanced usage docs."""

from .ext import InvenioOAuthClient, InvenioOAuthClientREST
from .oauth import oauth_link_external_id, oauth_unlink_external_id
from .proxies import current_oauthclient

__version__ = "6.1.1"

__all__ = (
    "__version__",
    "current_oauthclient",
    "InvenioOAuthClient",
    "InvenioOAuthClientREST",
    "oauth_link_external_id",
    "oauth_unlink_external_id",
)
