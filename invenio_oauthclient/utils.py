# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2023 CERN.
# Copyright (C) 2024 Graz University of Technology.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Utility methods."""

from flask import current_app, request, session
from flask_principal import RoleNeed
from invenio_db.utils import rebuild_encrypted_properties
from uritools import uricompose, urisplit
from werkzeug.local import LocalProxy
from werkzeug.utils import import_string

from .models import RemoteToken

try:
    # itsdangerous < 2.1.0
    from itsdangerous import TimedJSONWebSignatureSerializer
except ImportError:
    # itsdangerous >= 2.1.0
    from invenio_base.jws import TimedJSONWebSignatureSerializer


_security = LocalProxy(lambda: current_app.extensions["security"])


serializer = LocalProxy(
    lambda: TimedJSONWebSignatureSerializer(
        current_app.config["SECRET_KEY"],
        expires_in=current_app.config["OAUTHCLIENT_STATE_EXPIRES"],
    )
)


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


def remove_none_values(user_data):
    """Remove None values from the user data."""
    del_keys = []
    for key, value in list(user_data.items()):
        if isinstance(value, dict):
            remove_none_values(value)
            if value == {}:
                del_keys.append(key)
        if value is None:
            del_keys.append(key)
    for key in del_keys:
        del user_data[key]


def get_safe_redirect_target(arg="next"):
    """Get URL to redirect to and ensure that it is local.

    :param arg: URL argument.
    :returns: The redirect target or ``None``.
    """
    allowed_hosts = current_app.config.get("APP_ALLOWED_HOSTS") or []
    for target in request.args.get(arg), request.referrer:
        if target:
            redirect_uri = urisplit(target)
            if redirect_uri.host in allowed_hosts:
                return target
            elif redirect_uri.path:
                return uricompose(
                    path=redirect_uri.getpath(),
                    query=redirect_uri.getquery(),
                    fragment=redirect_uri.getfragment(),
                )
    return None


def obj_or_import_string(value, default=None):
    """Import string or return object."""
    if isinstance(value, str):
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
    for key, value in data.items():
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
    current_app.logger.info("rebuilding RemoteToken.access_token...")
    rebuild_encrypted_properties(old_key, RemoteToken, ["access_token"])


def _get_csrf_disabled_param():
    """Return the right param to disable CSRF depending on WTF-Form version.

    From Flask-WTF 0.14.0, `csrf_enabled` param has been deprecated in favor of
    `meta={csrf: True/False}`.
    """
    import flask_wtf
    from pkg_resources import parse_version

    supports_meta = parse_version(flask_wtf.__version__) >= parse_version("0.14.0")
    return dict(meta={"csrf": False}) if supports_meta else dict(csrf_enabled=False)


def load_user_role_needs(identity):
    """Add User/RoleNeed to the logged in user whenever identity is loaded."""
    if identity.id is None:
        # no user is logged in
        return

    needs = set()

    roles_ids = session.get("unmanaged_roles_ids", [])
    for role_id in roles_ids:
        needs.add(RoleNeed(role_id))

    identity.provides |= needs
