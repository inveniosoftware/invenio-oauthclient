# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2016-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Views for OAuth."""

from flask_admin.contrib.sqla import ModelView
from invenio_accounts.admin import UserIdentityView, user_identity_adminview

from .models import RemoteAccount, RemoteToken


def _(x):
    """Identity."""
    return x


class RemoteAccountView(ModelView):
    """Flask-Admin view to manage remote accounts from invenio-oauthclient."""

    can_view_details = True

    column_list = (
        "id",
        "user_id",
        "client_id",
        "extra_data",
        "remote_tokens",
    )

    remote_account_columns = (
        "id",
        "user_id",
        "client_id",
        "extra_data",
    )

    column_searchable_list = column_sortable_list = remote_account_columns

    column_filters = (
        "id",
        "user_id",
        "client_id",
    )

    column_default_sort = ("id", True)

    column_display_all_relations = True
    inline_models = (RemoteToken,)

    column_labels = {
        "id": _("ID"),
        "user_id": _("User ID"),
        "client_id": _("Client ID"),
    }


class RemoteTokenView(ModelView):
    """Flask-Admin view to manage remote tokens from invenio-oauthclient."""

    can_view_details = True

    column_list = (
        "id_remote_account",
        "token_type",
    )

    column_searchable_list = column_sortable_list = column_list

    column_filters = (
        "id_remote_account",
        "token_type",
    )

    form_columns = (
        "remote_account",
        "token_type",
    )

    column_labels = {
        "id_remote_account": _("ID Remote Account"),
    }


remote_account_adminview = {
    "model": RemoteAccount,
    "modelview": RemoteAccountView,
    "category": _("User Management"),
    "name": _("Linked accounts"),
}


remote_token_adminview = {
    "model": RemoteToken,
    "modelview": RemoteTokenView,
    "category": _("User Management"),
    "name": _("Linked account tokens"),
}

__all__ = (
    "remote_account_adminview",
    "remote_token_adminview",
    "user_identity_adminview",
)
