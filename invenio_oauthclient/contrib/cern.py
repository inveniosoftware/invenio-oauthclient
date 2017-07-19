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

"""Pre-configured remote application for enabling sign in/up with CERN.

**Usage:**

1. Edit your configuration and add:

   .. code-block:: python

       import copy

       from invenio_oauthclient.contrib import cern

       CERN_REMOTE_APP = copy.deepcopy(cern.REMOTE_APP)
       CERN_REMOTE_APP["params"].update(dict(request_token_params={
           "resource": "changeme.cern.ch",  # replace with your server
           "scope": "Name Email Bio Groups",
       }))

       OAUTHCLIENT_REMOTE_APPS = dict(
           cern=CERN_REMOTE_APP,
       )

       CERN_APP_CREDENTIALS = dict(
           consumer_key="changeme",
           consumer_secret="changeme",
       )

  Note, if you want to use the CERN sandbox, use ``cern.REMOTE_SANDBOX_APP``
  instead of ``cern.REMOTE_APP``.

2. Register a new application with CERN. When registering the
   application ensure that the *Redirect URI* points to:
   ``http://localhost:5000/oauth/authorized/cern/`` (note, CERN does not
   allow localhost to be used, thus testing on development machines is
   somewhat complicated by this).


3. Grab the *Client ID* and *Client Secret* after registering the application
   and add them to your instance configuration (``invenio.cfg``):

   .. code-block:: python

       CERN_APP_CREDENTIALS = dict(
           consumer_key="<CLIENT ID>",
           consumer_secret="<CLIENT SECRET>",
       )

4. Now login using CERN OAuth:
   http://localhost:5000/oauth/login/cern/.

5. Also, you should see CERN listed under Linked accounts:
   http://localhost:5000/account/settings/linkedaccounts/

By default the CERN module will try first look if a link already exists
between a CERN account and a user. If no link is found, the user is asked
to provide an email address to sign-up.

In templates you can add a sign in/up link:

.. code-block:: jinja

    <a href="{{ url_for("invenio_oauthclient.login", remote_app="cern") }}">
      Sign in with CERN
    </a>
"""

import copy
import re
from datetime import datetime, timedelta

from flask import current_app, g, redirect, session, url_for
from flask_login import current_user
from flask_principal import AnonymousIdentity, RoleNeed, UserNeed, \
    identity_changed, identity_loaded
from invenio_db import db

from invenio_oauthclient.models import RemoteAccount
from invenio_oauthclient.proxies import current_oauthclient
from invenio_oauthclient.utils import oauth_link_external_id, \
    oauth_unlink_external_id

OAUTHCLIENT_CERN_HIDDEN_GROUPS = (
    'All Exchange People',
    'CERN Users',
    'cern-computing-postmasters',
    'cern-nice2000-postmasters',
    'CMF FrontEnd Users',
    'CMF_NSC_259_NSU',
    'Domain Users',
    'GP Apply Favorites Redirection',
    'GP Apply NoAdmin',
    'info-terminalservices',
    'info-terminalservices-members',
    'IT Web IT',
    'NICE Deny Enforce Password-protected Screensaver',
    'NICE Enforce Password-protected Screensaver',
    'NICE LightWeight Authentication WS Users',
    'NICE MyDocuments Redirection (New)',
    'NICE Profile Redirection',
    'NICE Terminal Services Users',
    'NICE Users',
    'NICE VPN Users',
)
"""Tunable list of groups to be hidden."""

OAUTHCLIENT_CERN_HIDDEN_GROUPS_RE = (
    re.compile(r'Users by Letter [A-Z]'),
    re.compile(r'building-[\d]+'),
    re.compile(r'Users by Home CERNHOME[A-Z]'),
)
"""Tunable list of regexps of groups to be hidden."""

OAUTHCLIENT_CERN_REFRESH_TIMEDELTA = timedelta(minutes=-5)
"""Default interval for refreshing CERN extra data (e.g. groups)."""

OAUTHCLIENT_CERN_SESSION_KEY = 'identity.cern_provides'
"""Name of session key where CERN roles are stored."""

REMOTE_APP = dict(
    title='CERN',
    description='Connecting to CERN Organization.',
    icon='',
    authorized_handler='invenio_oauthclient.handlers'
                       ':authorized_signup_handler',
    disconnect_handler='invenio_oauthclient.contrib.cern'
                       ':disconnect_handler',
    signup_handler=dict(
        info='invenio_oauthclient.contrib.cern:account_info',
        setup='invenio_oauthclient.contrib.cern:account_setup',
        view='invenio_oauthclient.handlers:signup_handler',
    ),
    params=dict(
        base_url='https://oauth.web.cern.ch/',
        request_token_url=None,
        access_token_url='https://oauth.web.cern.ch/OAuth/Token',
        access_token_method='POST',
        authorize_url='https://oauth.web.cern.ch/OAuth/Authorize',
        app_key='CERN_APP_CREDENTIALS',
        content_type='application/json',
        request_token_params={'scope': 'Name Email Bio Groups',
                              'show_login': 'true'}
    )
)
"""CERN Remote Application."""

REMOTE_SANDBOX_APP = copy.deepcopy(REMOTE_APP)
"""CERN Sandbox Remote Application."""

REMOTE_SANDBOX_APP['params'].update(dict(
    base_url='https://test-oauth.web.cern.ch/',
    access_token_url='https://test-oauth.web.cern.ch/OAuth/Token',
    authorize_url='https://test-oauth.web.cern.ch/OAuth/Authorize',
))

REMOTE_APP_RESOURCE_API_URL = 'https://oauthresource.web.cern.ch/api/Me'
REMOTE_APP_RESOURCE_SCHEMA = 'http://schemas.xmlsoap.org/claims/'


def find_remote_by_client_id(client_id):
    """Return a remote application based with given client ID."""
    for remote in current_oauthclient.oauth.remote_apps.values():
        if remote.name == 'cern' and remote.consumer_key == client_id:
            return remote


def fetch_groups(groups):
    """Prepare list of allowed group names.

    :param groups: The complete list of groups.
    :returns: A filtered list of groups.
    """
    hidden_groups = current_app.config.get(
        'OAUTHCLIENT_CERN_HIDDEN_GROUPS', OAUTHCLIENT_CERN_HIDDEN_GROUPS)
    hidden_groups_re = current_app.config.get(
        'OAUTHCLIENT_CERN_HIDDEN_GROUPS_RE',
        OAUTHCLIENT_CERN_HIDDEN_GROUPS_RE)
    groups = [group for group in groups if group not in hidden_groups]
    filter_groups = []
    for regexp in hidden_groups_re:
        for group in groups:
            if regexp.match(group):
                filter_groups.append(group)
    groups = [group for group in groups if group not in filter_groups]

    return groups


def account_groups(account, resource, refresh_timedelta=None):
    """Fetch account groups from resource if necessary."""
    updated = datetime.utcnow()
    modified_since = updated
    if refresh_timedelta is not None:
        modified_since += refresh_timedelta
    modified_since = modified_since.isoformat()
    last_update = account.extra_data.get('updated', modified_since)

    if last_update > modified_since:
        return account.extra_data.get('groups', [])

    groups = fetch_groups(resource['Group'])
    account.extra_data.update(
        groups=groups,
        updated=updated.isoformat(),
    )
    return groups


def extend_identity(identity, groups):
    """Extend identity with roles based on CERN groups."""
    provides = set([UserNeed(current_user.email)] + [
        RoleNeed('{0}@cern.ch'.format(name)) for name in groups
    ])
    identity.provides |= provides
    session[OAUTHCLIENT_CERN_SESSION_KEY] = provides


def disconnect_identity(identity):
    """Disconnect identity from CERN groups."""
    provides = session.pop(OAUTHCLIENT_CERN_SESSION_KEY, {})
    identity.provides -= provides


def get_dict_from_response(response):
    """Prepare new mapping with 'Value's groupped by 'Type'."""
    result = {}
    if getattr(response, '_resp') and response._resp.code > 400:
        return result

    for i in response.data:
        # strip the schema from the key
        k = i['Type'].replace(REMOTE_APP_RESOURCE_SCHEMA, '')
        result.setdefault(k, list())
        result[k].append(i['Value'])
    return result


def get_resource(remote):
    """Query CERN Resources to get user info and groups."""
    cached_resource = session.pop('cern_resource', None)
    if cached_resource:
        return cached_resource

    response = remote.get(REMOTE_APP_RESOURCE_API_URL)
    dict_response = get_dict_from_response(response)
    session['cern_resource'] = dict_response
    return dict_response


def account_info(remote, resp):
    """Retrieve remote account information used to find local user."""
    resource = get_resource(remote)

    email = resource['EmailAddress'][0]
    external_id = resource['uidNumber'][0]
    nice = resource['CommonName'][0]
    name = resource['DisplayName'][0]

    return dict(
        user=dict(
            email=email.lower(),
            profile=dict(username=nice, full_name=name),
        ),
        external_id=external_id, external_method='cern',
        active=True
    )


def disconnect_handler(remote, *args, **kwargs):
    """Handle unlinking of remote account."""
    if not current_user.is_authenticated:
        return current_app.login_manager.unauthorized()

    account = RemoteAccount.get(user_id=current_user.get_id(),
                                client_id=remote.consumer_key)
    external_id = account.extra_data.get('external_id')

    if external_id:
        oauth_unlink_external_id(dict(id=external_id, method='cern'))
    if account:
        with db.session.begin_nested():
            account.delete()

    disconnect_identity(g.identity)

    return redirect(url_for('invenio_oauthclient_settings.index'))


def account_setup(remote, token, resp):
    """Perform additional setup after user have been logged in."""
    resource = get_resource(remote)

    with db.session.begin_nested():
        external_id = resource['uidNumber'][0]

        # Set CERN person ID in extra_data.
        token.remote_account.extra_data = {
            'external_id': external_id,
        }
        groups = account_groups(token.remote_account, resource)
        assert not isinstance(g.identity, AnonymousIdentity)
        extend_identity(g.identity, groups)

        user = token.remote_account.user

        # Create user <-> external id link.
        oauth_link_external_id(user, dict(id=external_id, method='cern'))


@identity_changed.connect
def on_identity_changed(sender, identity):
    """Store groups in session whenever identity changes.

    :param identity: The user identity where information are stored.
    """
    if isinstance(identity, AnonymousIdentity):
        return

    client_id = current_app.config['CERN_APP_CREDENTIALS']['consumer_key']
    account = RemoteAccount.get(
        user_id=current_user.get_id(),
        client_id=client_id,
    )
    groups = []
    if account:
        remote = find_remote_by_client_id(client_id)
        resource = get_resource(remote)
        refresh = current_app.config.get(
            'OAUTHCLIENT_CERN_REFRESH_TIMEDELTA',
            OAUTHCLIENT_CERN_REFRESH_TIMEDELTA
        )
        groups.extend(
            account_groups(account, resource, refresh_timedelta=refresh)
        )

    extend_identity(identity, groups)


@identity_loaded.connect
def on_identity_loaded(sender, identity):
    """Store groups in session whenever identity is loaded."""
    identity.provides.update(session.get(OAUTHCLIENT_CERN_SESSION_KEY, []))
