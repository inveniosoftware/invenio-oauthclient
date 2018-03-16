# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2016-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Views for OAuth."""

from __future__ import absolute_import, print_function

from flask_admin.contrib.sqla import ModelView

from .models import RemoteAccount, RemoteToken, UserIdentity


def _(x):
    """Identity."""
    return x


class RemoteAccountView(ModelView):
    """Flask-Admin view to manage remote accounts from invenio-oauthclient."""

    can_view_details = True

    column_list = (
        'id',
        'user_id',
        'client_id',
        'extra_data',
        'remote_tokens',
    )

    remote_account_columns = (
        'id',
        'user_id',
        'client_id',
        'extra_data',
    )

    column_searchable_list = column_sortable_list = remote_account_columns

    column_filters = ('id', 'user_id', 'client_id', )

    column_default_sort = ('id', True)

    column_display_all_relations = True
    inline_models = (RemoteToken,)

    column_labels = {
        'id': _('ID'),
        'user_id': _('User ID'),
        'client_id': _('Client ID'),
    }


class RemoteTokenView(ModelView):
    """Flask-Admin view to manage remote tokens from invenio-oauthclient."""

    can_view_details = True

    column_list = (
        'id_remote_account',
        'token_type',
    )

    column_searchable_list = \
        column_sortable_list = \
        column_list

    column_filters = (
        'id_remote_account',
        'token_type',
    )

    form_columns = (
        'remote_account',
        'token_type',
    )

    column_labels = {
        'id_remote_account': _('ID Remote Account'),
    }


class UserIdentityView(ModelView):
    """Flask-Admin view to manage user identities from invenio-oauthclient."""

    can_view_details = True
    can_create = False

    column_list = (
        'id',
        'method',
        'id_user',
        'user.email',
    )

    column_searchable_list = \
        column_sortable_list = \
        column_list

    column_filters = (
        'id',
        'method',
        'id_user',
        'user.email',
    )

    column_labels = {
        'user.email': _("Email"),
        'id_user': _("User ID"),
    }


remote_account_adminview = {
    'model': RemoteAccount,
    'modelview': RemoteAccountView,
    'category': _('User Management'),
    'name': _('Linked accounts'),
}

remote_token_adminview = {
    'model': RemoteToken,
    'modelview': RemoteTokenView,
    'category': _('User Management'),
    'name': _('Linked account tokens'),
}

user_identity_adminview = {
    'model': UserIdentity,
    'modelview': UserIdentityView,
    'category': _('User Management'),
    'name': _('Linked account identities'),
}

__all__ = ('remote_account_adminview', 'remote_token_adminview',
           'user_identity_adminview')
