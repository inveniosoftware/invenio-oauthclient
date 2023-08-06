# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2023 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Handlers for customizing oauthclient endpoints."""

from functools import wraps

from flask import abort, current_app
from flask_login import current_user
from invenio_accounts.models import Role
from invenio_accounts.proxies import current_datastore
from werkzeug.utils import import_string

from ..models import RemoteAccount


def make_handler(f, remote, with_response=True):
    """Make a handler for authorized and disconnect callbacks.

    :param f: Callable or an import path to a callable
    """
    if isinstance(f, str):
        f = import_string(f)

    @wraps(f)
    def inner(*args, **kwargs):
        if with_response:
            return f(args[0], remote, *args[1:], **kwargs)
        else:
            return f(remote, *args, **kwargs)

    return inner


def authorized_handler(f, authorized_response):
    """Handles an OAuth callback.

    As authorized_handler is deprecated in favor of authorized_response,
    it's has to be wrapped with handler which will be executed
    at the proper time.
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        data = authorized_response()
        return f(*((data,) + args), **kwargs)

    return decorated


def require_more_than_one_external_account(f):
    """Require that the user has more than one external account for login.

    If the user only has one linked external account and no means for logging
    in via local credentials, the decorated function won't be executed.
    This decorator is useful for disconnect handlers, to prevent users from
    disconnecting their last potential means of authentication.
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        if current_user.is_anonymous:
            return f(*args, **kwargs)

        local_login_enabled = current_app.config.get(
            "ACCOUNTS_LOCAL_LOGIN_ENABLED", True
        )
        password_set = current_user.password is not None
        local_login_possible = local_login_enabled and password_set

        remote_apps = current_app.config["OAUTHCLIENT_REMOTE_APPS"]
        accounts = RemoteAccount.query.filter_by(user_id=current_user.get_id()).all()

        # find out all of the linked external accounts for the user
        # that are currently configured and not hidden
        consumer_keys = set()
        remote_apps = current_app.config["OAUTHCLIENT_REMOTE_APPS"]
        for name, remote_app in remote_apps.items():
            if not remote_app.get("hide", False):
                consumer_keys.add(name)  # backcompat with v1.5.4
                remote_app_config = current_app.config[remote_app["params"]["app_key"]]
                consumer_keys.add(remote_app_config["consumer_key"])

        linked_accounts = [acc for acc in accounts if acc.client_id in consumer_keys]

        # execute the function only if local login is possible, or
        # there's more than one linked external account
        if local_login_possible or len(linked_accounts) > 1:
            return f(*args, **kwargs)

        else:
            abort(400)

    return decorated


def _role_needs_update(role_obj, new_role_dict):
    """Checks if role needs to be updated."""
    if role_obj.name != new_role_dict.get(
        "name"
    ) or role_obj.description != new_role_dict.get("description"):
        return True
    return False


def create_or_update_roles(groups):
    """Create/update DB roles based on the groups provided."""
    roles_ids = set()
    for group in groups:
        existing_role = current_datastore.find_role_by_id(group["id"])
        if existing_role and existing_role.is_managed:
            current_app.logger.exception(
                f'Error while syncing roles: A managed role with id: ${group["id"]} already exists'
            )
            continue
        existing_role_by_name = current_datastore.find_role(group["name"])
        if existing_role_by_name and existing_role_by_name.is_managed:
            current_app.logger.exception(
                f'Error while syncing roles: A managed role with name: ${group["name"]} already exists'
            )
            continue
        if not existing_role:
            role = current_datastore.create_role(
                id=group["id"],
                name=group["name"],
                description=group.get("description"),
                is_managed=False,
            )
            roles_ids.add(role.id)
        elif existing_role and _role_needs_update(existing_role, group):
            role_to_update = Role(
                id=group["id"],
                name=group["name"],
                description=group.get("description"),
                is_managed=False,
            )
            role = current_datastore.update_role(role_to_update)
            roles_ids.add(role.id)
        else:
            roles_ids.add(existing_role.id)

    current_datastore.commit()
    return roles_ids
