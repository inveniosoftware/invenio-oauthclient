# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2014, 2015 CERN.
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

from __future__ import absolute_import

from invenio_testing import InvenioTestCase

from mock import MagicMock


class OAuth2ClientTestCase(InvenioTestCase):

    """Helper test case to make oauth client testing easier."""

    @property
    def config(self):
        cfg = super(OAuth2ClientTestCase, self).config
        cfg['PACKAGES'] = [
            'invenio_oauthclient',
            'invenio_accounts',
            'invenio_base',
        ]
        cfg['DEBUG'] = False
        return cfg

    def mock_response(self, app=None, data=None):
        """Mock the oauth response from a remote application."""
        from invenio_oauthclient.client import oauth

        # Mock oauth remote application
        oauth.remote_apps[app].handle_oauth2_response = MagicMock(
            return_value=data or {
                "access_token": "test_access_token",
                "scope": "",
                "token_type": "bearer"
            }
        )
