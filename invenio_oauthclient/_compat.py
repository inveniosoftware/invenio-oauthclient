# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Compat."""

from __future__ import absolute_import, print_function

try:
    from flask_login.utils import _create_identifier
except ImportError:
    from flask_login import _create_identifier
