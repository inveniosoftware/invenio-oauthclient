import os

from invenio_db import db

from invenio_oauthclient.contrib.settings import OAuthSettingsHelper
from invenio_oauthclient.errors import OAuthResponseError
from invenio_oauthclient.handlers import authorized_signup_handler, oauth_error_handler
from invenio_oauthclient.handlers.utils import require_more_than_one_external_account
from invenio_oauthclient.handlers.rest import oauth_resp_remote_error_handler, response_handler
from invenio_oauthclient.models import RemoteAccount
from invenio_oauthclient.utils import oauth_link_external_id, oauth_unlink_external_id

from flask import current_app, redirect, url_for
from flask_login import current_user

"""Pre-configured remote application for enabling sign in/up with GitLab.

Besides the public https://gitlab.com, GitLab can also be installed on
premises (e.g, ``https://gitlab.example.com``). By default, ``gitlab.com``
is used, but you can set custom values for your own/on premises instance.
The sections below cover both cases.

1. First thing to do is to create a new application in GitLab
(see https://docs.gitlab.com/ee/integration/oauth_provider.html for
instructions on how to register it). Basically, you wanna go to
``https://<gitlab-address>/-/profile/applications``. Make sure to:
  * check scopes ``read_user`` and ``email``
  * set _redirect URI_ to ``CFG_SITE_SECURE_URL/oauth/authorized/gitlab/``


2. Once the application is registered you'll have access to the *Application ID*
   and *Secret* keys. Those will be used in the next step inside your (Invenio)
   instance configuration file (``invenio.cfg``).


3a. Edit your Invenio instance configuration and add the GitLab app secret keys:

   .. code-block:: python

        from invenio_oauthclient.contrib import gitlab

        OAUTHCLIENT_REMOTE_APPS = dict(
            gitlab=github.REMOTE_APP,
        )

        GITLAB_APP_CREDENTIALS = dict(
            consumer_key='<APPLICATION ID>',
            consumer_secret='<APPLICATION SECRET>',
        )


3b. *IF* the GitLab server is different from ``gitlab.com``, running on your
    premises at ``gitlab.example.com``, for example, you have to say so:

   .. code-block:: python

        from invenio_oauthclient.contrib import gitlab

        _gl_ = 'https://gitlab.exampl.com'

        mygitlab = gitlab.GitlabOAuthSettingsHelper(
            access_token_url = f"{_gl_}/oauth/token"
            authorize_url = f"{_gl_}/oauth/authorize"
            base_url = f"{_gl_}/api/v4"
        )

        OAUTHCLIENT_REMOTE_APPS = dict(
            gitlab = mygitlab.remote_app,
        )

        GITLAB_APP_CREDENTIALS = dict(
            consumer_key = '<APPLICATION ID>',
            consumer_secret = '<APPLICATION SECRET>',
        )


5. Now go to ``CFG_SITE_SECURE_URL/oauth/login/gitlab/`` (e.g.
   http://127.0.0.1:5000/oauth/login/gitlab/)

6. Also, you should see GitLab listed under Linked accounts:
   http://127.0.0.1:5000/account/settings/linkedaccounts/

By default the GitLab module will try first look if a link already exists
between a GitLab account and a user. If no link is found, the module tries to
retrieve the user email address from GitHub to match it with a local user. If
this fails, the user is asked to provide an email address to sign-up.

In templates you can add a sign in/up link:

.. code-block:: jinja

    <a href='{{url_for('invenio_oauthclient.login', remote_app='gitlab')}}'>
      Sign in with GitLab
    </a>

For more details you can play with a :doc:`working example <examplesapp>`.
"""


class GitlabOAuthSettingsHelper(OAuthSettingsHelper):
    def __init__(self,
        title=None,
        description=None,
        base_url=None,
        app_key=None,
        icon=None,
        access_token_url=None,
        authorize_url=None,
        access_token_method="POST",
        request_token_params=None,
        request_token_url=None,
        precedence_mask=None,
        ):

        _glcom_ = 'https://gitlab.com'
        kwargs = dict(
            access_token_method ="POST",
            request_token_url = request_token_url,
            access_token_url= (
                access_token_url or f"{_glcom_}/oauth/token"
            ),
            authorize_url = (
                authorize_url or f"{_glcom_}/oauth/authorize"
            ),
            base_url = (
                base_url or f"{_glcom_}/api/v4"
            ),
            app_key = (
                app_key or "GITLAB_APP_CREDENTIALS"
            ),
            request_token_params = (
                request_token_params or {'scope': 'read_user email'}
            ),
            precedence_mask = (
                precedence_mask or {'email': True}
            ),
            title = title or "Gitlab",
            icon = icon or "fa fa-gitlab",
            description = (
                description or "Gitlab/OAuth server instance"
            ),
        )
        super().__init__(**kwargs)

    def get_handlers(self):
        return dict(
            authorized_handler='invenio_oauthclient.handlers:authorized_signup_handler',
            disconnect_handler=gitlab_disconnect_handler,
            signup_handler=dict(
                info=gitlab_account_info,
                setup=gitlab_account_setup,
                view='invenio_oauthclient.handlers:signup_handler',
            )
        )

    def get_rest_handlers(self):
        return dict(
            authorized_handler='invenio_oauthclient.handlers.rest:authorized_signup_handler',
            disconnect_handler=gitlab_disconnect_rest_handler,
            signup_handler=dict(
                info=gitlab_account_info,
                setup=gitlab_account_setup,
                view='invenio_oauthclient.handlers.rest:signup_handler',
            ),
            response_handler='invenio_oauthclient.handlers.rest:default_remote_response_handler',
            authorized_redirect_url='/',
            disconnect_redirect_url='/',
            signup_redirect_url='/',
            error_redirect_url='/'
        )


def _request_user_info(remote, resp):
    # We could here, like in contrib.github, use an auxiliary library (eg, python-gitlab)
    # I've chosen not to use to not add a dependency for such small use.
    # The equivalent in python-gitlab for the request below is:
    # ```
    # > import gitlab
    # > gl = gitlab.Gitlab('https://gitlab.com', oauth_token=resp['access_token'])
    # > gl.auth()
    # > user_info = gl.user.attributes
    # ```
    import requests
    headers={'Authorization': f'{resp["token_type"]} {resp["access_token"]}'}
    r = requests.get(remote.base_url + '/user', headers=headers)
    return r.json()


def gitlab_account_info(remote, resp):
    user_info = _request_user_info(remote, resp)
    _id = str(user_info['id'])
    _email = user_info['email']
    _username = user_info['username']
    _full_name = user_info['name']
    return dict(
        user = dict(
            email = _email,
            profile = dict(
                username = _username,
                full_name = _full_name
            ),
        ),
        external_id = _id,
        external_method = 'gitlab'
    )


def gitlab_account_setup(remote, token, resp):
    user_info = _request_user_info(remote, resp)

    _id = str(user_info['id'])
    _email = user_info['email']
    _username = user_info['username']
    _full_name = user_info['name']

    with db.session.begin_nested():
        token.remote_account.extra_data = {'username': _username, 'id': _id}

        # Create user <-> external id link.
        oauth_link_external_id(
            token.remote_account.user, dict(
                id=_id,
                method='gitlab')
        )


@require_more_than_one_external_account
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


def gitlab_disconnect_handler(remote, *args, **kwargs):
    """Handle unlinking of remote account.

    :param remote: The remote application.
    :returns: The HTML response.
    """
    _disconnect(remote, *args, **kwargs)
    return redirect(url_for('invenio_oauthclient_settings.index'))


def gitlab_disconnect_rest_handler(remote, *args, **kwargs):
    """Handle unlinking of remote account.

    :param remote: The remote application.
    :returns: The HTML response.
    """
    _disconnect(remote, *args, **kwargs)
    redirect_url = current_app.config['OAUTHCLIENT_REST_REMOTE_APPS'][
        remote.name]['disconnect_redirect_url']
    return response_handler(remote, redirect_url)

@oauth_error_handler
def authorized(resp, remote):
    """Authorized callback handler for GitLab.

    :param resp: The response.
    :param remote: The remote application.
    """
    if resp and 'error' in resp:
        if resp['error'] == 'bad_verification_code':
            return redirect(url_for('invenio_oauthclient.login',
                                    remote_app='gitlab'))
        elif resp['error'] in ['incorrect_client_credentials',
                               'redirect_uri_mismatch']:
            raise OAuthResponseError(
                'Application mis-configuration in GitLab', remote, resp
            )

    return authorized_signup_handler(resp, remote)


@oauth_resp_remote_error_handler
def authorized_rest(resp, remote):
    """Authorized callback handler for GitLab.

    :param resp: The response.
    :param remote: The remote application.
    """
    if resp and 'error' in resp:
        if resp['error'] == 'bad_verification_code':
            return redirect(url_for('invenio_oauthclient.rest_login',
                                    remote_app='gitlab'))
        elif resp['error'] in ['incorrect_client_credentials',
                               'redirect_uri_mismatch']:
            raise OAuthResponseError(
                'Application mis-configuration in GitLab', remote, resp
            )

    return authorized_signup_rest_handler(resp, remote)


_gitlab = GitlabOAuthSettingsHelper()

BASE_APP = _gitlab.base_app
"""GitLab.COM base application configuration."""

REMOTE_APP = _gitlab.remote_app
"""GitLab.COM remote application configuration."""

REMOTE_REST_APP = _gitlab.remote_rest_app
"""GitLab.COM remote REST application configuration."""
