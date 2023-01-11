# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Account settings blueprint for oauthclient."""

from operator import itemgetter

import six
from flask import Blueprint, current_app, render_template, request
from flask_breadcrumbs import register_breadcrumb
from flask_login import current_user, login_required
from flask_menu import register_menu
from invenio_i18n import lazy_gettext as _
from invenio_theme.proxies import current_theme_icons
from speaklater import make_lazy_string

from ..models import RemoteAccount
from ..proxies import current_oauthclient

blueprint = Blueprint(
    "invenio_oauthclient_settings",
    __name__,
    url_prefix="/account/settings/linkedaccounts",
    static_folder="../static",
    template_folder="../templates",
)


@blueprint.route("/", methods=["GET", "POST"])
@login_required
@register_menu(
    blueprint,
    "settings.oauthclient",
    _(
        "%(icon)s Linked accounts",
        icon=make_lazy_string(lambda: f'<i class="{current_theme_icons.link}"></i>'),
    ),
    order=3,
    active_when=lambda: request.endpoint.startswith("invenio_oauthclient_settings."),
    visible_when=lambda: bool(current_app.config.get("OAUTHCLIENT_REMOTE_APPS"))
    is not False,
)
@register_breadcrumb(
    blueprint, "breadcrumbs.settings.oauthclient", _("Linked accounts")
)
def index():
    """List linked accounts."""
    oauth = current_oauthclient.oauth

    services = []
    service_map = {}
    i = 0

    for appid, conf in six.iteritems(current_app.config["OAUTHCLIENT_REMOTE_APPS"]):
        if not conf.get("hide", False):
            services.append(
                dict(
                    appid=appid,
                    title=conf["title"],
                    icon=conf.get("icon", None),
                    description=conf.get("description", None),
                    account=None,
                )
            )
            service_map[oauth.remote_apps[appid].consumer_key] = i
            i += 1

    # Fetch already linked accounts
    accounts = RemoteAccount.query.filter_by(user_id=current_user.get_id()).all()

    for a in accounts:
        if a.client_id in service_map:
            services[service_map[a.client_id]]["account"] = a

    # Sort according to title
    services.sort(key=itemgetter("title"))

    # Check if local login is possible
    local_login_enabled = current_app.config.get("ACCOUNTS_LOCAL_LOGIN_ENABLED", True)
    password_set = current_user.password is not None
    local_login_possible = local_login_enabled and password_set

    return render_template(
        "invenio_oauthclient/settings/index.html",
        services=services,
        only_external_login=not local_login_possible,
    )
