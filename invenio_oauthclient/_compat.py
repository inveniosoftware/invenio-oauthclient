# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2018 CERN.
# Copyright (C) 2024 Graz University of Technology.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Compat."""

import urllib

import werkzeug

try:
    from flask_login.utils import _create_identifier
except ImportError:
    from flask_login import _create_identifier


def monkey_patch_werkzeug():
    """Patch top level removed modules."""
    try:
        from werkzeug import cached_property
    except ImportError:
        werkzeug.cached_property = werkzeug.utils.cached_property
        werkzeug.parse_options_header = werkzeug.http.parse_options_header
        werkzeug.url_quote = urllib.parse.quote
        werkzeug.url_decode = urllib.parse.parse_qs
        werkzeug.url_encode = urllib.parse.urlencode

    try:
        # werkzeug >= 3.0 has removed following functions from werkzeug.urls
        from werkzeug.urls import url_quote
    except ImportError:
        werkzeug.urls.url_quote = urllib.parse.quote
        werkzeug.urls.url_decode = urllib.parse.parse_qs
        werkzeug.urls.url_encode = urllib.parse.urlencode
