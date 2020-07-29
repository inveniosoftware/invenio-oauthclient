# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Pre-configured remote application for enabling sign in/up with GitHub.

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
            consumer_key='changeme',
            consumer_secret='changeme',
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
            consumer_key='<CLIENT ID>',
            consumer_secret='<CLIENT SECRET>',
        )

5. Now go to ``CFG_SITE_SECURE_URL/oauth/login/github/`` (e.g.
   http://localhost:4000/oauth/login/github/)

6. Also, you should see GitHub listed under Linked accounts:
   http://localhost:4000/account/settings/linkedaccounts/

By default the GitHub module will try first look if a link already exists
between a GitHub account and a user. If no link is found, the module tries to
retrieve the user email address from GitHub to match it with a local user. If
this fails, the user is asked to provide an email address to sign-up.

In templates you can add a sign in/up link:

.. code-block:: jinja

    <a href='{{url_for('invenio_oauthclient.login', remote_app='github')}}'>
      Sign in with GitHub
    </a>

For more details you can play with a :doc:`working example <examplesapp>`.
"""

import github3
from flask import current_app, redirect, url_for
from flask_login import current_user
from invenio_db import db

from invenio_oauthclient.errors import OAuthResponseError
from invenio_oauthclient.handlers import authorized_signup_handler, \
    oauth_error_handler
from invenio_oauthclient.handlers.rest import \
    authorized_signup_handler as authorized_signup_rest_handler
from invenio_oauthclient.handlers.rest import \
    oauth_resp_remote_error_handler, response_handler
from invenio_oauthclient.models import RemoteAccount
from invenio_oauthclient.utils import oauth_link_external_id, \
    oauth_unlink_external_id

BASE_APP = dict(
    title='GitHub',
    description='Software collaboration platform.',
    icon='fa fa-github',
    params=dict(
        request_token_params={'scope': 'user,user:email'},
        base_url='https://api.github.com/',
        request_token_url=None,
        access_token_url='https://github.com/login/oauth/access_token',
        access_token_method='POST',
        authorize_url='https://github.com/login/oauth/authorize',
        app_key='GITHUB_APP_CREDENTIALS',
    )
)
REMOTE_APP = dict(BASE_APP)
REMOTE_APP.update(dict(
    authorized_handler='invenio_oauthclient.handlers'
                       ':authorized_signup_handler',
    disconnect_handler='invenio_oauthclient.contrib.github'
                       ':disconnect_handler',
    signup_handler=dict(
        info='invenio_oauthclient.contrib.github:account_info',
        setup='invenio_oauthclient.contrib.github:account_setup',
        view='invenio_oauthclient.handlers:signup_handler',
    )
))
"""GitHub remote application configuration."""


REMOTE_REST_APP = dict(BASE_APP)
REMOTE_REST_APP.update(dict(
    authorized_handler='invenio_oauthclient.handlers.rest'
                       ':authorized_signup_handler',
    disconnect_handler='invenio_oauthclient.contrib.github'
                       ':disconnect_rest_handler',
    signup_handler=dict(
        info='invenio_oauthclient.contrib.github:account_info',
        setup='invenio_oauthclient.contrib.github:account_setup',
        view='invenio_oauthclient.handlers.rest:signup_handler',
    ),
    response_handler=(
        'invenio_oauthclient.handlers.rest:default_remote_response_handler'
    ),
    authorized_redirect_url='/',
    disconnect_redirect_url='/',
    signup_redirect_url='/',
    error_redirect_url='/'

))
"""GitHub remote rest application configuration."""


def _extract_email(gh):
    """Get user email from github."""
    return next(
        (x.email for x in gh.emails() if x.verified and x.primary), None)


def account_info(remote, resp):
    """Retrieve remote account information used to find local user.

    It returns a dictionary with the following structure:

    .. code-block:: python

        {
            'user': {
                'email': '...',
                'profile': {
                    'username': '...',
                    'full_name': '...',
                }
            },
            'external_id': 'github-unique-identifier',
            'external_method': 'github',
        }

    Information inside the user dictionary are available for other modules.
    For example, they are used from the module invenio-userprofiles to fill
    the user profile.

    :param remote: The remote application.
    :param resp: The response.
    :returns: A dictionary with the user information.
    """
    gh = github3.login(token=resp['access_token'])
    me = gh.me()
    return dict(
        user=dict(
            email=_extract_email(gh),
            profile=dict(
                username=me.login,
                full_name=me.name,
            ),
        ),
        external_id=str(me.id),
        external_method='github'
    )


def account_setup(remote, token, resp):
    """Perform additional setup after user have been logged in.

    :param remote: The remote application.
    :param token: The token value.
    :param resp: The response.
    """
    gh = github3.login(token=resp['access_token'])
    with db.session.begin_nested():
        me = gh.me()

        token.remote_account.extra_data = {'login': me.login, 'id': me.id}

        # Create user <-> external id link.
        oauth_link_external_id(
            token.remote_account.user, dict(
                id=str(me.id),
                method='github')
        )


@oauth_error_handler
def authorized(resp, remote):
    """Authorized callback handler for GitHub.

    :param resp: The response.
    :param remote: The remote application.
    """
    if resp and 'error' in resp:
        if resp['error'] == 'bad_verification_code':
            # See https://developer.github.com/v3/oauth/#bad-verification-code
            # which recommends starting auth flow again.
            return redirect(url_for('invenio_oauthclient.login',
                                    remote_app='github'))
        elif resp['error'] in ['incorrect_client_credentials',
                               'redirect_uri_mismatch']:
            raise OAuthResponseError(
                'Application mis-configuration in GitHub', remote, resp
            )

    return authorized_signup_handler(resp, remote)


@oauth_resp_remote_error_handler
def authorized_rest(resp, remote):
    """Authorized callback handler for GitHub.

    :param resp: The response.
    :param remote: The remote application.
    """
    if resp and 'error' in resp:
        if resp['error'] == 'bad_verification_code':
            # See https://developer.github.com/v3/oauth/#bad-verification-code
            # which recommends starting auth flow again.
            return redirect(url_for('invenio_oauthclient.rest_login',
                                    remote_app='github'))
        elif resp['error'] in ['incorrect_client_credentials',
                               'redirect_uri_mismatch']:
            raise OAuthResponseError(
                'Application mis-configuration in GitHub', remote, resp
            )

    return authorized_signup_rest_handler(resp, remote)


def _disconnect(remote, *args, **kwargs):
    """Handle unlinking of remote account.

    :param remote: The remote application.
    :returns: The HTML response.
    """
    if not current_user.is_authenticated:
        return current_app.login_manager.unauthorized()

    remote_account = RemoteAccount.get(user_id=current_user.get_id(),
                                       client_id=remote.consumer_key)
    external_method = 'github'
    external_ids = [i.id for i in current_user.external_identifiers
                    if i.method == external_method]

    if external_ids:
        oauth_unlink_external_id(dict(id=external_ids[0],
                                      method=external_method))
    if remote_account:
        with db.session.begin_nested():
            remote_account.delete()


def disconnect_handler(remote, *args, **kwargs):
    """Handle unlinking of remote account.

    :param remote: The remote application.
    :returns: The HTML response.
    """
    _disconnect(remote, *args, **kwargs)
    return redirect(url_for('invenio_oauthclient_settings.index'))


def disconnect_rest_handler(remote, *args, **kwargs):
    """Handle unlinking of remote account.

    :param remote: The remote application.
    :returns: The HTML response.
    """
    _disconnect(remote, *args, **kwargs)
    redirect_url = current_app.config['OAUTHCLIENT_REST_REMOTE_APPS'][
        remote.name]['disconnect_redirect_url']
    return response_handler(remote, redirect_url)
