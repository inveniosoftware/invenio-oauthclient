# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2018 University of Chicago.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Pre-configured remote application for enabling sign in/up with Globus.

1. Edit your configuration and add:

   .. code-block:: python

        from invenio_oauthclient.contrib import globus

        OAUTHCLIENT_REMOTE_APPS = dict(
            globus=globus.REMOTE_APP,
        )

        GLOBUS_APP_CREDENTIALS = dict(
            consumer_key='changeme',
            consumer_secret='changeme',
        )

2. Register a Globus application at `https://developers.globus.org/` with the
   `Redirect URL` as `http://localhost:5000/oauth/authorized/globus/`. For
   full documentation on all app fields, see:
   `https://docs.globus.org/api/auth/developer-guide/#register-app`

4. Grab the *Client ID* and *Client Secret* after registering the application
   and add them to your instance configuration (``invenio.cfg``):

   .. code-block:: python

        GLOBUS_APP_CREDENTIALS = dict(
            consumer_key='<CLIENT ID>',
            consumer_secret='<CLIENT SECRET>',
        )

5. Now go to your site: http://localhost:5000/oauth/authorized/globus/

6. You should see Globus listed under Linked accounts:
   http://localhost:5000/account/settings/linkedaccounts/

"""

from flask import current_app, redirect, url_for
from flask_login import current_user
from invenio_db import db

from invenio_oauthclient.errors import OAuthResponseError
from invenio_oauthclient.handlers.rest import response_handler
from invenio_oauthclient.models import RemoteAccount
from invenio_oauthclient.utils import oauth_link_external_id, \
    oauth_unlink_external_id

BASE_APP = dict(
    title='Globus',
    description='Research data management simplified.',
    icon='',
    params=dict(
        request_token_params={'scope': 'openid email profile'},
        base_url='https://auth.globus.org/',
        request_token_url=None,
        access_token_url='https://auth.globus.org/v2/oauth2/token',
        access_token_method='POST',
        authorize_url='https://auth.globus.org/v2/oauth2/authorize',
        app_key='GLOBUS_APP_CREDENTIALS',
    )
)

REMOTE_APP = dict(BASE_APP)
REMOTE_APP.update(dict(
    authorized_handler='invenio_oauthclient.handlers'
                       ':authorized_signup_handler',
    disconnect_handler='invenio_oauthclient.contrib.globus'
                       ':disconnect_handler',
    signup_handler=dict(
        info='invenio_oauthclient.contrib.globus:account_info',
        setup='invenio_oauthclient.contrib.globus:account_setup',
        view='invenio_oauthclient.handlers:signup_handler',
    )
))
"""Globus remote application configuration."""

REMOTE_REST_APP = dict(BASE_APP)
REMOTE_REST_APP.update(dict(
    authorized_handler='invenio_oauthclient.handlers.rest'
                       ':authorized_signup_handler',
    disconnect_handler='invenio_oauthclient.contrib.globus'
                       ':disconnect_rest_handler',
    signup_handler=dict(
        info='invenio_oauthclient.contrib.globus:account_info',
        setup='invenio_oauthclient.contrib.globus:account_setup',
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
"""Globus remote rest application configuration."""


GLOBUS_USER_INFO_URL = 'https://auth.globus.org/v2/oauth2/userinfo'
GLOBUS_USER_ID_URL = 'https://auth.globus.org/v2/api/identities'
GLOBUS_EXTERNAL_METHOD = 'globus'


def get_dict_from_response(response):
    """Check for errors in the response and return the resulting JSON."""
    if getattr(response, '_resp') and response._resp.code > 400:
        raise OAuthResponseError(
                'Application mis-configuration in Globus', None, response
            )

    return response.data


def get_user_info(remote):
    """Get user information from Globus.

    See the docs here for v2/oauth/userinfo:
    https://docs.globus.org/api/auth/reference/
    """
    response = remote.get(GLOBUS_USER_INFO_URL)
    user_info = get_dict_from_response(response)
    response.data['username'] = response.data['preferred_username']
    if '@' in response.data['username']:
        user_info['username'], _ = response.data['username'].split('@')
    return user_info


def get_user_id(remote, email):
    """Get the Globus identity for a users given email.

    A Globus ID is a UUID that can uniquely identify a Globus user. See the
    docs here for v2/api/identities
    https://docs.globus.org/api/auth/reference/
    """
    try:
        url = '{}?usernames={}'.format(GLOBUS_USER_ID_URL, email)
        user_id = get_dict_from_response(remote.get(url))
        return user_id['identities'][0]['id']
    except KeyError:
        # If we got here the response was successful but the data was invalid.
        # It's likely the URL is wrong but possible the API has changed.
        raise OAuthResponseError('Failed to fetch user id, likely server '
                                 'mis-configuration', None, remote)


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
            'external_id': 'globus-unique-identifier',
            'external_method': 'globus',
        }

    Information inside the user dictionary are available for other modules.
    For example, they are used from the module invenio-userprofiles to fill
    the user profile.

    :param remote: The remote application.
    :param resp: The response.
    :returns: A dictionary with the user information.
    """
    info = get_user_info(remote)

    return {
        'user': {
            'email': info['email'],
            'profile': {
                'username': info['username'],
                'full_name': info['name']
            },
        },
        'external_id': get_user_id(remote, info['preferred_username']),
        'external_method': GLOBUS_EXTERNAL_METHOD
    }


def account_setup(remote, token, resp):
    """Perform additional setup after user have been logged in.

    :param remote: The remote application.
    :param token: The token value.
    :param resp: The response.
    """
    info = get_user_info(remote)
    user_id = get_user_id(remote, info['preferred_username'])
    with db.session.begin_nested():

        token.remote_account.extra_data = {
            'login': info['username'],
            'id': user_id}

        # Create user <-> external id link.
        oauth_link_external_id(
            token.remote_account.user, dict(
                id=user_id,
                method=GLOBUS_EXTERNAL_METHOD)
        )


def _disconnect(remote, *args, **kwargs):
    """Handle unlinking of remote account.

    :param remote: The remote application.
    :returns: The HTML response.
    """
    if not current_user.is_authenticated:
        return current_app.login_manager.unauthorized()

    remote_account = RemoteAccount.get(user_id=current_user.get_id(),
                                       client_id=remote.consumer_key)
    external_ids = [i.id for i in current_user.external_identifiers
                    if i.method == GLOBUS_EXTERNAL_METHOD]

    if external_ids:
        oauth_unlink_external_id(dict(id=external_ids[0],
                                      method=GLOBUS_EXTERNAL_METHOD))

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
