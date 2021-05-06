# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Compat."""

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
        werkzeug.url_quote = werkzeug.urls.url_quote
        werkzeug.url_decode = werkzeug.urls.url_decode
        werkzeug.url_encode = werkzeug.urls.url_encode
