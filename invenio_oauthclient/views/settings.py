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

"""Account settings blueprint for oauthclient."""

from __future__ import absolute_import

from operator import itemgetter

import six
from flask import Blueprint, current_app, render_template, request
from flask_babelex import gettext as _
from flask_breadcrumbs import register_breadcrumb
from flask_menu import register_menu
from flask_security import current_user, login_required

from ..models import RemoteAccount

blueprint = Blueprint(
    'invenio_oauthclient_settings',
    __name__,
    url_prefix='/account/settings/linkedaccounts',
    static_folder='../static',
    template_folder='../templates',
)


@blueprint.route('/', methods=['GET', 'POST'])
@login_required
@register_menu(
    blueprint, 'settings.oauthclient',
    _('%(icon)s Linked accounts', icon='<i class="fa fa-link fa-fw"></i>'),
    order=3,
    active_when=lambda: request.endpoint.startswith(
        'invenio_oauthclient_settings.')
)
@register_breadcrumb(
    blueprint, 'breadcrumbs.settings.oauthclient', _('Linked accounts')
)
def index():
    """List linked accounts."""
    oauth = current_app.extensions['oauthlib.client']

    services = []
    service_map = {}
    i = 0

    for appid, conf in six.iteritems(
            current_app.config['OAUTHCLIENT_REMOTE_APPS']):
        if not conf.get('hide', False):
            services.append(dict(
                appid=appid,
                title=conf['title'],
                icon=conf.get('icon', None),
                description=conf.get('description', None),
                account=None
            ))
            service_map[oauth.remote_apps[appid].consumer_key] = i
            i += 1

    # Fetch already linked accounts
    accounts = RemoteAccount.query.filter_by(
        user_id=current_user.get_id()
    ).all()

    for a in accounts:
        if a.client_id in service_map:
            services[service_map[a.client_id]]['account'] = a

    # Sort according to title
    services.sort(key=itemgetter('title'))

    return render_template(
        'invenio_oauthclient/settings/index.html',
        services=services
    )
