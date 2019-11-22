# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Test case for models."""

from __future__ import absolute_import

from invenio_db import db

from invenio_oauthclient.models import RemoteAccount, RemoteToken


def test_get_create_remote_account(app, models_fixture):
    """Test create remote account."""
    created_acc = RemoteAccount.create(1, 'dev', dict(somekey='somevalue'))
    assert created_acc

    retrieved_acc = RemoteAccount.get(1, 'dev')
    assert created_acc.id == retrieved_acc.id
    assert retrieved_acc.extra_data == dict(somekey='somevalue')

    db.session.delete(retrieved_acc)
    assert RemoteAccount.get(1, 'dev') is None


def test_get_create_remote_token(app, models_fixture):
    """Test create remote token."""
    existing_email = 'existing@inveniosoftware.org'
    datastore = app.extensions['invenio-accounts'].datastore
    user = datastore.find_user(email=existing_email)

    t = RemoteToken.create(user.id, 'dev', 'mytoken', 'mysecret')
    assert t
    assert t.token() == ('mytoken', 'mysecret')

    acc = RemoteAccount.get(user.id, 'dev')
    assert acc
    assert t.remote_account.id == acc.id
    assert t.token_type == ''

    t2 = RemoteToken.create(
        user.id, 'dev', 'mytoken2', 'mysecret2',
        token_type='t2'
    )
    assert t2.remote_account.id == acc.id
    assert t2.token_type == 't2'

    t3 = RemoteToken.get(user.id, 'dev')
    t4 = RemoteToken.get(user.id, 'dev', token_type='t2')
    assert t4.token() != t3.token()

    assert RemoteToken.query.count() == 2
    acc.delete()
    assert RemoteToken.query.count() == 0


def test_get_regression(app, models_fixture):
    """Test regression."""
    datastore = app.extensions['invenio-accounts'].datastore

    email2 = 'test2@inveniosoftware.org'
    email3 = 'test3@inveniosoftware.org'

    user2 = datastore.find_user(email=email2)
    user3 = datastore.find_user(email=email3)

    t3 = RemoteToken.create(user2.id, 'dev', 'mytoken', 'mysecret')
    t4 = RemoteToken.create(user3.id, 'dev', 'mytoken', 'mysecret')

    assert RemoteToken.get(user2.id, 'dev').remote_account.user_id == \
        t3.remote_account.user_id
    assert RemoteToken.get(user3.id, 'dev').remote_account.user_id == \
        t4.remote_account.user_id


def test_repr(app, models_fixture):
    """Test representation of RemoteAccount and RemoteToken."""
    datastore = app.extensions['invenio-accounts'].datastore
    user = datastore.find_user(email='existing@inveniosoftware.org')

    assert 'Remote Token <token_type=type access_token=****oken>' == \
           repr(RemoteToken.create(user.id, 'dev',
                                   'mytoken', 'mysecret',
                                   token_type='type'))

    assert 'Remote Account <id=1, user_id=1>' == \
           repr(RemoteAccount.get(user.id, 'dev'))
