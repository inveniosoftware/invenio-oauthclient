# SPDX-FileCopyrightText: 2015-2018 CERN.
# SPDX-License-Identifier: MIT

"""Blueprints for oauthclient."""

from .client import blueprint as client_blueprint
from .settings import blueprint as settings_blueprint

blueprints = [
    client_blueprint,
    settings_blueprint,
]
