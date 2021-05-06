# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Blueprints for oauthclient."""

from .client import blueprint as client_blueprint
from .settings import blueprint as settings_blueprint

blueprints = [
    client_blueprint,
    settings_blueprint,
]
