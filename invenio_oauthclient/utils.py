# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Utility methods to help find, authenticate or register a remote user."""

import six
from flask import after_this_request, current_app, request
from flask_security import login_user, logout_user
from flask_security.confirmable import requires_confirmation
from invenio_accounts.models import User
from invenio_accounts.utils import register_user
from invenio_db import db
from invenio_db.utils import rebuild_encrypted_properties
from itsdangerous import TimedJSONWebSignatureSerializer
from sqlalchemy.exc import IntegrityError
from uritools import uricompose, urisplit
from werkzeug.local import LocalProxy
from werkzeug.utils import import_string

from .errors import AlreadyLinkedError
from .models import RemoteAccount, RemoteToken, UserIdentity

_security = LocalProxy(lambda: current_app.extensions['security'])

_datastore = LocalProxy(lambda: _security.datastore)


serializer = LocalProxy(
    lambda: TimedJSONWebSignatureSerializer(
        current_app.config['SECRET_KEY'],
        expires_in=current_app.config['OAUTHCLIENT_STATE_EXPIRES'],
    )
)


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

    :param client_id: The client id.
    :param account_info: The dictionary with the account info.
        (Default: ``None``)
    :param access_token: The access token. (Default: ``None``)
    :returns: A :class:`invenio_accounts.models.User` instance or ``None``.
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
        email = account_info.get('user', {}).get('email')
        if email:
            return User.query.filter_by(email=email).one_or_none()
    return None


def oauth_authenticate(client_id, user, require_existing_link=False):
    """Authenticate an oauth authorized callback.

    :param client_id: The client id.
    :param user: A user instance.
    :param require_existing_link: If ``True``, check if remote account exists.
        (Default: ``False``)
    :returns: ``True`` if the user is successfully authenticated.
    """
    # Authenticate via the access token (access token used to get user_id)
    if not requires_confirmation(user):
        after_this_request(_commit)
        if login_user(user, remember=False):
            if require_existing_link:
                account = RemoteAccount.get(user.id, client_id)
                if account is None:
                    logout_user()
                    return False
            return True
    return False


def filter_user_info(user_info, precedence_mask):
    """Filter the user info dictionary according to the precedence mask.

    :param user_info: The user info dictionary.
    :param precedence_mask: The precedence mask to use.
    """
    # for each of the user info values, check if they are supposed
    # to take precedence over user input (as per precedence mask)
    for key, user_info_value in list(user_info.items()):
        precedence_value = precedence_mask.get(key, True)
        info_val_dict = isinstance(user_info_value, dict)
        prec_val_dict = isinstance(precedence_value, dict)

        if info_val_dict and prec_val_dict:
            # if both values in the mask and user_info are dicts,
            # investigate deeper
            filter_user_info(user_info_value, precedence_mask[key])

        elif prec_val_dict:
            # the precedence mask says it's a dict, but it is actually
            # a different value... remove this inconsistent user_info value
            user_info.pop(key, None)

        elif not precedence_value:
            user_info.pop(key, None)


def patch_dictionary(orig_dict, patch_dict):
    """Replace the fields mentioned in the patch, while leaving others as is.

    Note: The first argument's content will be changed during the process.

    :param orig_dict: A dictionary.
    :param patch_dict: The dictionary whose values should take precedence.
    """
    for key in patch_dict.keys():
        val = patch_dict[key]
        orig_val = orig_dict.get(key)

        if isinstance(val, dict) and isinstance(orig_val, dict):
            patch_dictionary(orig_val, val)
        else:
            orig_dict[key] = val


def remove_csrf_tokens(user_data):
    """Remove CSRF tokens from the user data."""
    user_data.pop("csrf_token", None)
    for key, value in list(user_data.items()):
        if isinstance(value, dict):
            remove_csrf_tokens(value)


def oauth_register(form, user_info=None, precedence_mask=None):
    """Register user if possible.

    :param form: A form instance.
    :param user_info: The user info dictionary.
    :returns: A :class:`invenio_accounts.models.User` instance.
    """
    if form.validate():
        data = form.to_dict()

        # let relevant information from the OAuth service's user info
        # have precedence over the values specified by the user
        if user_info:
            default_mask = {"email": True}
            filter_user_info(user_info, precedence_mask or default_mask)
            patch_dictionary(data, user_info)

        # remove the CSRF tokens to avoid unexpected keyword arguments
        remove_csrf_tokens(data)
        user = register_user(**data)
        _datastore.commit()
        return user


def oauth_link_external_id(user, external_id=None):
    """Link a user to an external id.

    :param user: A :class:`invenio_accounts.models.User` instance.
    :param external_id: The external id associated with the user.
        (Default: ``None``)
    :raises invenio_oauthclient.errors.AlreadyLinkedError: Raised if already
        exists a link.
    """
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
    """Unlink a user from an external id.

    :param external_id: The external id associated with the user.
    """
    with db.session.begin_nested():
        UserIdentity.query.filter_by(id=external_id['id'],
                                     method=external_id['method']).delete()


def get_safe_redirect_target(arg='next'):
    """Get URL to redirect to and ensure that it is local.

    :param arg: URL argument.
    :returns: The redirect target or ``None``.
    """
    allowed_hosts = current_app.config.get('APP_ALLOWED_HOSTS') or []
    for target in request.args.get(arg), request.referrer:
        if target:
            redirect_uri = urisplit(target)
            if redirect_uri.host in allowed_hosts:
                return target
            elif redirect_uri.path:
                return uricompose(
                    path=redirect_uri.getpath(),
                    query=redirect_uri.getquery(),
                    fragment=redirect_uri.getfragment()
                )
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


def _create_registrationform(*args, **kwargs):
    """Default registration form after external auth success."""
    class RegistrationForm(_security.confirm_register_form):
        password = None
        recaptcha = None
        submit = None  # defined in the template
    return RegistrationForm(*args, **kwargs)


def create_registrationform(*args, **kwargs):
    """Make a registration form."""
    func = current_app.config["OAUTHCLIENT_SIGNUP_FORM"]
    return func(*args, **kwargs)


def create_csrf_disabled_registrationform(remote):
    """Create a registration form with CSRF disabled."""
    func = current_app.config["OAUTHCLIENT_SIGNUP_FORM"]
    return func(oauth_remote_app=remote, **_get_csrf_disabled_param())


def fill_form(form, data):
    """Prefill form with data.

    :param form: The form to fill.
    :param data: The data to insert in the form.
    :returns: A pre-filled form.
    """
    for (key, value) in data.items():
        if hasattr(form, key):
            field = getattr(form, key)
            if isinstance(value, dict):
                fill_form(field, value)
            elif field is not None:
                field.data = value
    return form


def rebuild_access_tokens(old_key):
    """Rebuild the access token field when the SECRET_KEY is changed.

    Fixes users' login

    :param old_key: the old SECRET_KEY.
    """
    current_app.logger.info('rebuilding RemoteToken.access_token...')
    rebuild_encrypted_properties(old_key, RemoteToken, ['access_token'])


def _get_csrf_disabled_param():
    """Return the right param to disable CSRF depending on WTF-Form version.

    From Flask-WTF 0.14.0, `csrf_enabled` param has been deprecated in favor of
    `meta={csrf: True/False}`.
    """
    import flask_wtf
    from pkg_resources import parse_version
    supports_meta = parse_version(flask_wtf.__version__) >= parse_version(
        "0.14.0")
    return dict(meta={'csrf': False}) if supports_meta else \
        dict(csrf_enabled=False)
