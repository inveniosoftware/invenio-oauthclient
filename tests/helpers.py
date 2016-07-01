# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2014, 2015, 2016 CERN.
#
# Invenio is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# Invenio is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Invenio; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.

"""OAuth client test utility functions."""

from flask_login import _create_identifier
from mock import MagicMock

from invenio_oauthclient.views.client import serializer


def get_state(app='test'):
    return serializer.dumps({'app': app, 'sid': _create_identifier(),
                             'next': None, })


def mock_response(oauth, remote_app='test', data=None):
    """Mock the oauth response to use the remote."""
    oauth.remote_apps[remote_app].handle_oauth2_response = MagicMock(
        return_value=data
    )


def mock_remote_get(oauth, remote_app='test', data=None):
    """Mock the oauth remote get response."""
    oauth.remote_apps[remote_app].get = MagicMock(
        return_value=data
    )
