import os

from invenio_db import db

from invenio_oauthclient.contrib.settings import OAuthSettingsHelper
from invenio_oauthclient.handlers import authorized_signup_handler, oauth_error_handler
from invenio_oauthclient.handlers.utils import require_more_than_one_external_account
from invenio_oauthclient.models import RemoteAccount
from invenio_oauthclient.utils import oauth_link_external_id, oauth_unlink_external_id

from flask import current_app, redirect, url_for
from flask_login import current_user

#_GITLAB_SERVER_ = 'gitlab.com'
#OAUTHCLIENT_REMOTE_APPS = {
#    "gitlab": dict(
#        description = 'Gitlab-GMAP login authentication',
#        icon = 'fa fa-gitlab',
#        title = 'Gitlab',
#        params = dict(
#            base_url = f'https://{_GITLAB_SERVER_}/api/v4',
#            authorize_url = f'https://{_GITLAB_SERVER_}/oauth/authorize',
#            access_token_url = f'https://{_GITLAB_SERVER_}/oauth/token',
#            request_token_params = {'scope': 'email read_user'},
#            consumer_secret = os.environ['CONSUMER_SECRET'],
#            consumer_key = os.environ['CONSUMER_KEY'],
#            access_token_method = 'POST',
#            request_token_url = None,
#        ),
#        precedence_mask = {
#            "email": True,
#        },
#    )
#}



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
                request_token_params or {'scope': 'read_user'}
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
            disconnect_handler=gitlab_disconnect_handler,
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
    if r.status_code != 200:
        return None
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
        token.remote_account.extra_data = {'login': _username, 'id': _id}

        # Create user <-> external id link.
        oauth_link_external_id(
            token.remote_account.user, dict(
                id=_id,
                method='gitlab')
        )


@require_more_than_one_external_account
def gitlab_disconnect_handler(remote, *args, **kwargs):
    if not current_user.is_authenticated:
        return current_app.login_manager.unauthorized()

    remote_account = RemoteAccount.get(user_id=current_user.get_id(),
                                       client_id=remote.consumer_key)
    external_method = 'gitlab'
    external_ids = [i.id for i in current_user.external_identifiers
                    if i.method == external_method]

    if external_ids:
        oauth_unlink_external_id(dict(id=external_ids[0],
                                      method=external_method))
    if remote_account:
        with db.session.begin_nested():
            remote_account.delete()


_gitlab = GitlabOAuthSettingsHelper()

BASE_APP = _gitlab.base_app
"""GitLab.COM base application configuration."""

REMOTE_APP = _gitlab.remote_app
"""GitLab.COM remote application configuration."""

REMOTE_REST_APP = _gitlab.remote_rest_app
"""GitLab.COM remote REST application configuration."""

