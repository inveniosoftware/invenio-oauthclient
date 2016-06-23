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

"""Utility methods to help find, authenticate or register a remote user."""

from __future__ import absolute_import, print_function

import six
from flask import after_this_request, current_app, request
from flask_security import login_user, logout_user
from flask_security.confirmable import requires_confirmation
from flask_security.registerable import register_user
from invenio_accounts.models import User
from invenio_db import db
from sqlalchemy.exc import IntegrityError
from uritools import urisplit
from werkzeug.local import LocalProxy
from werkzeug.utils import import_string
from wtforms.fields.core import FormField

from .errors import AlreadyLinkedError
from .models import RemoteAccount, RemoteToken, UserIdentity

_security = LocalProxy(lambda: current_app.extensions['security'])

_datastore = LocalProxy(lambda: _security.datastore)


def _commit(response=None):
    _datastore.commit()
    return response


def _get_external_id(account_info):
    """Get external id from account info."""
    if all(k in account_info for k in ('external_id', 'external_method')):
        return dict(id=account_info['external_id'],
                    method=account_info['external_method'])
    return None


def oauth_get_user(client_id, account_info=None, access_token=None):
    """Retrieve user object for the given request.

    Uses either the access token or extracted account information to retrieve
    the user object.
    """
    if access_token:
        token = RemoteToken.get_by_token(client_id, access_token)
        if token:
            return token.remote_account.user

    if account_info:
        external_id = _get_external_id(account_info)
        if external_id:
            user_identity = UserIdentity.query.filter_by(
                id=external_id['id'], method=external_id['method']).first()
            if user_identity:
                return user_identity.user
        if account_info.get('email'):
            return User.query.filter_by(email=account_info['email']).first()
    return None


def oauth_authenticate(client_id, user, require_existing_link=False,
                       remember=False):
    """Authenticate an oauth authorized callback."""
    # Authenticate via the access token (access token used to get user_id)
    if not requires_confirmation(user):
        after_this_request(_commit)
        if login_user(user):
            if require_existing_link:
                account = RemoteAccount.get(user.id, client_id)
                if account is None:
                    logout_user()
                    return False
            return True
    return False


def oauth_register(form):
    """Register user if possible."""
    if form.validate():
        data = form.to_dict()
        if not data.get('password'):
            data['password'] = ''
        user = register_user(**data)
        if not data['password']:
            user.password = None
        _datastore.commit()
        return user


def oauth_link_external_id(user, external_id=None):
    """Link a user to an external id."""
    try:
        with db.session.begin_nested():
            db.session.add(UserIdentity(
                id=external_id['id'],
                method=external_id['method'],
                id_user=user.id
            ))
    except IntegrityError:
        raise AlreadyLinkedError(user, external_id)


def oauth_unlink_external_id(external_id):
    """Unlink a user from an external id."""
    with db.session.begin_nested():
        UserIdentity.query.filter_by(id=external_id['id'],
                                     method=external_id['method']).delete()


def is_local_url(target):
    """Determine if URL is a local."""
    server_name = current_app.config['SERVER_NAME']
    test_url = urisplit(target)
    return not test_url.host or test_url.scheme in ('http', 'https') and \
        server_name == test_url.host


def get_safe_redirect_target(arg='next'):
    """Get URL to redirect to and ensure that it is local."""
    for target in request.args.get(arg), request.referrer:
        if target and is_local_url(target):
            return target
    return None


def obj_or_import_string(value, default=None):
    """Import string or return object."""
    if isinstance(value, six.string_types):
        return import_string(value)
    elif value:
        return value
    return default


def load_or_import_from_config(key, app=None, default=None):
    """Load or import value from config."""
    app = app or current_app
    imp = app.config.get(key)
    return obj_or_import_string(imp, default=default)


def registrationform_cls():
    """Make a registration form."""
    class RegistrationForm(_security.confirm_register_form):
        password = None
        recaptcha = None
    return RegistrationForm


def fill_form(form, data):
    """Prefill form."""
    for (key, value) in data.items():
        if hasattr(form, key):
            if isinstance(value, dict):
                fill_form(getattr(form, key), value)
            else:
                getattr(form, key).data = value
    return form


def disable_csrf(form):
    """Disable CSRF protection."""
    form.csrf_enabled = False
    for f in form:
        if isinstance(f, FormField):
            disable_csrf(f.form)
    return form
