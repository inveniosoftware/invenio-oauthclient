# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2016-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Views for OAuth."""
from flask import url_for
from flask_admin import Admin
from invenio_db import db

from invenio_oauthclient import InvenioOAuthClient
from invenio_oauthclient.admin import remote_account_adminview, \
    remote_token_adminview, user_identity_adminview


def test_admin(app):
    """Test flask-admin interace."""
    InvenioOAuthClient(app)

    assert isinstance(remote_account_adminview, dict)
    assert isinstance(remote_token_adminview, dict)
    assert isinstance(user_identity_adminview, dict)

    assert 'model' in remote_account_adminview
    assert 'modelview' in remote_account_adminview
    assert 'model' in remote_token_adminview
    assert 'modelview' in remote_token_adminview
    assert 'model' in user_identity_adminview
    assert 'modelview' in user_identity_adminview

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
