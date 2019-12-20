# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""OAuth client test utility functions."""

from inspect import isfunction

import six
from mock import MagicMock
from six.moves.urllib_parse import parse_qs, urlencode, urlparse

from invenio_oauthclient._compat import _create_identifier
from invenio_oauthclient.views.client import serializer


def get_state(app='test'):
    """Get state."""
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


def check_redirect_location(resp, loc):
    """Check response redirect location."""
    assert resp._status_code == 302
    if isinstance(loc, six.string_types):
        assert resp.headers['Location'] == loc
    elif isfunction(loc):
        assert loc(resp.headers['Location'])


def check_response_redirect_url(response, expected_url):
    """Check response redirect url."""
    assert response.status_code == 302
    state = serializer.loads(
        parse_qs(urlparse(response.location).query)['state'][0])
    assert expected_url == state['next']


def check_response_redirect_url_args(response, expected_args):
    """Check response redirect url."""
    assert response.status_code == 302
    assert urlencode(expected_args) == urlparse(response.location).query
