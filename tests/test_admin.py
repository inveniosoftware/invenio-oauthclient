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

"""Views for OAuth."""
from flask import url_for
from flask_admin import Admin
from invenio_db import db

from invenio_oauthclient import InvenioOAuthClient
from invenio_oauthclient.admin import remote_account_adminview, \
    remote_token_adminview


def test_admin(app):
    """Test flask-admin interace."""
    InvenioOAuthClient(app)

    assert isinstance(remote_account_adminview, dict)
    assert isinstance(remote_token_adminview, dict)

    assert 'model' in remote_account_adminview
    assert 'modelview' in remote_account_adminview
    assert 'model' in remote_token_adminview
    assert 'modelview' in remote_token_adminview

    admin = Admin(app, name='Test')

    user_model = remote_account_adminview.pop('model')
    user_view = remote_account_adminview.pop('modelview')
    admin.add_view(user_view(user_model, db.session,
                             **remote_account_adminview))

    with app.app_context():
        # create user and save url for testing
        request_url = url_for('remoteaccount.index_view')

    with app.app_context():
        with app.test_client() as client:
            res = client.get(
                request_url,
                follow_redirects=True
            )
            assert res.status_code == 200
            assert 'Extra Data' in str(res.get_data())
            assert 'Tokens' in str(res.get_data())
