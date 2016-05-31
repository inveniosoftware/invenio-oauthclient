# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2014, 2016 CERN.
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

"""Pre-configured remote application for enabling sign in/up with GitHub.

**Usage:**

1. Ensure you have ``github3.py`` package installed:

   .. code-block:: console

      cdvirtualenv src/invenio-oauthclient
      pip install -e .[github]

2. Edit your configuration and add:

   .. code-block:: python

        from invenio_oauthclient.contrib import github

        OAUTHCLIENT_REMOTE_APPS = dict(
            github=github.REMOTE_APP,
        )

        GITHUB_APP_CREDENTIALS = dict(
            consumer_key="changeme",
            consumer_secret="changeme",
        )

3. Go to GitHub and register a new application:
   https://github.com/settings/applications/new. When registering the
   application ensure that the *Authorization callback URL* points to:
   ``CFG_SITE_SECURE_URL/oauth/authorized/github/`` (e.g.
   ``http://localhost:4000/oauth/authorized/github/`` for development).


4. Grab the *Client ID* and *Client Secret* after registering the application
   and add them to your instance configuration (``invenio.cfg``):

   .. code-block:: python

        GITHUB_APP_CREDENTIALS = dict(
            consumer_key="<CLIENT ID>",
            consumer_secret="<CLIENT SECRET>",
        )

5. Now go to ``CFG_SITE_SECURE_URL/oauth/login/github/`` (e.g.
   http://localhost:4000/oauth/login/github/)

6. Also, you should see GitHub listed under Linked accounts:
   http://localhost:4000//account/settings/linkedaccounts/

By default the GitHub module will try first look if a link already exists
between a GitHub account and a user. If no link is found, the module tries to
retrieve the user email address from GitHub to match it with a local user. If
this fails, the user is asked to provide an email address to sign-up.

In templates you can add a sign in/up link:

.. code-block:: jinja

    <a href="{{url_for('invenio_oauthclient.login', remote_app='github')}}">
      Sign in with GitHub
    </a>
"""

import github3
from flask import redirect, url_for

from invenio_oauthclient.errors import OAuthResponseError
from invenio_oauthclient.handlers import authorized_signup_handler, \
    oauth_error_handler

REMOTE_APP = dict(
    title='GitHub',
    description='Software collaboration platform.',
    icon='fa fa-github',
    authorized_handler="invenio_oauthclient.handlers"
                       ":authorized_signup_handler",
    disconnect_handler="invenio_oauthclient.handlers"
                       ":disconnect_handler",
    signup_handler=dict(
        info="invenio_oauthclient.contrib.github:account_info",
        setup="invenio_oauthclient.contrib.github:account_setup",
        view="invenio_oauthclient.handlers:signup_handler",
    ),
    params=dict(
        request_token_params={'scope': 'user,user:email'},
        base_url='https://api.github.com/',
        request_token_url=None,
        access_token_url="https://github.com/login/oauth/access_token",
        access_token_method='POST',
        authorize_url="https://github.com/login/oauth/authorize",
        app_key="GITHUB_APP_CREDENTIALS",
    )
)


def account_info(remote, resp):
    """Retrieve remote account information used to find local user."""
    gh = github3.login(token=resp['access_token'])
    ghuser = gh.user()
    email = ghuser.email
    if not email:
        record = next(gh.iter_emails(1))
        email = record['email'] if 'email' in record else None
    # FIXME get user informations accordly with invenio-userprofiles
    return dict(email=email, external_id=ghuser.id,
                external_method='github')


def account_setup(remote, token, resp):
    """Perform additional setup after user have been logged in."""
    pass


@oauth_error_handler
def authorized(resp, remote):
    """Authorized callback handler for GitHub."""
    if resp and 'error' in resp:
        if resp['error'] == 'bad_verification_code':
            # See https://developer.github.com/v3/oauth/#bad-verification-code
            # which recommends starting auth flow again.
            return redirect(url_for('invenio_oauthclient.login',
                                    remote_app='github'))
        elif resp['error'] in ['incorrect_client_credentials',
                               'redirect_uri_mismatch']:
            raise OAuthResponseError(
                "Application mis-configuration in GitHub", remote, resp
            )

    return authorized_signup_handler(resp, remote)
