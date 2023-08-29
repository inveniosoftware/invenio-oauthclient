# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2023 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""OAuth methods to help find, authenticate or register a remote user."""

from flask import after_this_request, current_app
from flask_security import login_user, logout_user
from flask_security.confirmable import confirm_user, requires_confirmation
from invenio_accounts.models import User
from invenio_accounts.utils import register_user
from werkzeug.local import LocalProxy

from .models import RemoteAccount, RemoteToken, UserIdentity
from .utils import (
    fill_form,
    filter_user_info,
    patch_dictionary,
    remove_csrf_tokens,
    remove_none_values,
)

_security = LocalProxy(lambda: current_app.extensions["security"])

_datastore = LocalProxy(lambda: _security.datastore)


def _commit(response=None):
    _datastore.commit()
    return response


def _get_external_id(account_info):
    """Get external id from account info."""
    if all(k in account_info for k in ("external_id", "external_method")):
        return dict(
            id=account_info["external_id"], method=account_info["external_method"]
        )
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
            user = UserIdentity.get_user(external_id["method"], external_id["id"])
            if user:
                return user
        email = account_info.get("user", {}).get("email")
        if email:
            return User.query.filter_by(email=email).one_or_none()
    return None


def oauth_authenticate(
    client_id, user, require_existing_link=False, require_user_confirmation=False
):
    """Authenticate an oauth authorized callback.

    :param client_id: The client id.
    :param user: A user instance.
    :param require_existing_link: If ``True``, check if remote account exists.
        (Default: ``False``)
    :returns: ``True`` if the user is successfully authenticated.
    """
    # this is for backwards compatibility and tests
    if require_user_confirmation:
        if requires_confirmation(user):
            return False

    # Authenticate via the access token (access token used to get user_id)
    after_this_request(_commit)
    if login_user(user):
        if require_existing_link:
            account = RemoteAccount.get(user.id, client_id)
            if account is None:
                logout_user()
                return False
        return True


def oauth_register(form, user_info=None, precedence_mask=None, signup_options={}):
    """Register user if possible.

    :param form: A form instance.
    :param user_info: The user info dictionary.
    :param precedence_mask: The precedence mask to use.
    :param signup_options: Extra signup options dict.
    :returns: A :class:`invenio_accounts.models.User` instance.
    """
    if form.validate():
        form_data = form.data

        # let relevant information from the OAuth service's user info
        # have precedence over the values specified by the user
        if user_info:
            default_mask = {"email": True}
            # act on form data so the `profile` is updated correctly
            filter_user_info(user_info, precedence_mask or default_mask)
            patch_dictionary(form_data, user_info)

        # re-populate the form after applying the precedence mask and
        # convert the form data to user model's data
        data = fill_form(form, form_data).to_dict()
        # see https://github.com/inveniosoftware/invenio-oauthclient/issues/275
        remove_none_values(data)
        # remove the CSRF tokens to avoid unexpected keyword arguments
        remove_csrf_tokens(data)

        send_register_msg = signup_options.get("send_register_msg", True)
        user = register_user(send_register_msg=send_register_msg, **data)
        auto_confirm = signup_options.get("auto_confirm", False)
        if auto_confirm:
            confirm_user(user)
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
    # Backward compatibility. Use UserIdentity directly instead of this method.
    UserIdentity.create(user, external_id["method"], external_id["id"])


def oauth_unlink_external_id(external_id):
    """Unlink a user from an external id.

    :param external_id: The external id associated with the user.
    """
    UserIdentity.delete_by_external_id(external_id["method"], external_id["id"])
