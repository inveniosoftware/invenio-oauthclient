# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2016 CERN.
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

"""Test utils."""

from __future__ import absolute_import, print_function

import pytest
from flask_security.confirmable import _security

from invenio_oauthclient.errors import AlreadyLinkedError
from invenio_oauthclient.models import RemoteAccount, RemoteToken
from invenio_oauthclient.utils import _get_external_id, oauth_authenticate, \
    oauth_get_user, oauth_link_external_id, oauth_unlink_external_id, \
    obj_or_import_string


def test_utilities(models_fixture):
    """Test utilities."""
    app = models_fixture
    datastore = app.extensions['invenio-accounts'].datastore
    assert obj_or_import_string('invenio_oauthclient.errors')

    # User
    existing_email = 'existing@inveniosoftware.org'
    user = datastore.find_user(email=existing_email)

    # Authenticate
    assert not _get_external_id({})
    assert not oauth_authenticate('dev', user, require_existing_link=True)

    _security.confirmable = True
    _security.login_without_confirmation = False
    user.confirmed_at = None
    assert not oauth_authenticate('dev', user)

    # Tokens
    t = RemoteToken.create(user.id, 'dev', 'mytoken', 'mysecret')
    assert \
        RemoteToken.get(user.id, 'dev', access_token='mytoken') == \
        RemoteToken.get_by_token('dev', 'mytoken')

    assert oauth_get_user('dev', access_token=t.access_token) == user
    assert \
        oauth_get_user('dev', account_info={'email': existing_email}) == user

    # Link user to external id
    external_id = {'id': '123', 'method': 'test_method'}
    oauth_link_external_id(user, external_id)

    with pytest.raises(AlreadyLinkedError):
        oauth_link_external_id(user, external_id)

    assert oauth_get_user('dev',
                          account_info={
                              'external_id': external_id['id'],
                              'external_method': external_id['method']
                          }) == user

    # Cleanup
    oauth_unlink_external_id(external_id)
    acc = RemoteAccount.get(user.id, 'dev')
    acc.delete()
