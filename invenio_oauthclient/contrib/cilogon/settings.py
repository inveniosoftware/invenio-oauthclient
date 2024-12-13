import requests
from invenio_oauthclient.contrib.settings import OAuthSettingsHelper


class CilogonSettingsHelper(OAuthSettingsHelper):

    def __init__(self, title=None,
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
                signup_options={"auto_confirm": True, "send_register_msg": False,},
                jwks_url=None,
                logout_url=None):
        endpoints = self.getEndpoints(base_url)
        self._user_info_url = endpoints['user_info_url']
        self._jwks_url = endpoints['jwks_url']
        super().__init__(title=title,
                         description=description or "CILOGON Comanage Registr",
                         base_url=base_url or "https://cilogon.org/jlab",
                         app_key=app_key or  "CILOGON_APP_CREDENTIALS",
                         icon=icon,
                         access_token_url=access_token_url or endpoints['access_token_url'],
                         authorize_url=authorize_url or endpoints['authorize_url'],
                         access_token_method=access_token_method or "POST",
                         request_token_params=request_token_params or {"scope": "openid email org.cilogon.userinfo profile "},
                         request_token_url=request_token_url,
                         precedence_mask=precedence_mask,
                         signup_options=signup_options,
                        )
        
        self._handlers = dict(
            authorized_handler="invenio_oauthclient.handlers:authorized_signup_handler",
            disconnect_handler="invenio_oauthclient.contrib.cilogon.handlers:disconnect_handler",
            signup_handler=dict(
                info="invenio_oauthclient.contrib.cilogon.handlers:info_handler",
                info_serializer="invenio_oauthclient.contrib.cilogon.handlers:info_serializer_handler",
                setup="invenio_oauthclient.contrib.cilogon.handlers:setup_handler",
                groups="invenio_oauthclient.contrib.cilogon.handlers:group_handler",
                groups_serializer="invenio_oauthclient.contrib.cilogon.handlers:group_serializer_handler",
                view="invenio_oauthclient.handlers:signup_handler",
            ),
        )
        self._rest_handlers = dict(
            authorized_handler="invenio_oauthclient.handlers.rest:authorized_signup_handler",
            disconnect_handler="invenio_oauthclient.contrib.cilogon.handlers:disconnect_rest_handler",
            signup_handler=dict(
                info="invenio_oauthclient.contrib.cilogon.handlers:info_handler",
                info_serializer="invenio_oauthclient.contrib.cilogon.handlers:info_serializer_handler",
                setup="invenio_oauthclient.contrib.cilogon.handlers:setup_handler",
                groups="invenio_oauthclient.contrib.cilogon.handlers:group_handler",
                groups_serializer="invenio_oauthclient.contrib.cilogon.handlers:group_rest_serializer_handler",
                view="invenio_oauthclient.handlers.rest:signup_handler",
            ),
            response_handler=(
                "invenio_oauthclient.handlers.rest:default_remote_response_handler"
            ),
            authorized_redirect_url="/",
            disconnect_redirect_url="/",
            signup_redirect_url="/",
            error_redirect_url="/",
        )

    def getEndpoints(self,base_url):
        url = base_url.rstrip('/')+'/.well-known/openid-configuration'
        try:
            r = requests.get(url=url,timeout=4,headers={'Content-Type':'application/json'})
            if r.status_code == 200:
                endpoints = r.json()
                return {'access_token_url':endpoints['token_endpoint'],
                'authorize_url':endpoints['authorization_endpoint'],
                'user_info_url':endpoints['userinfo_endpoint'],
                'jwks_url':endpoints['jwks_uri']
                }
            else:
                return {'access_token_url':None,
                'authorize_url':None,
                'user_info_url':None,
                'jwks_url':None
                }
        except Exception:
            return {'access_token_url':None,
                'authorize_url':None,
                'request_token_url':None,
                'user_info_url':None,
                'jwks_url':None
                }

    @property
    def user_info_url(self):
        """URL for the user info endpoint."""
        return self._user_info_url

    @property
    def jwks_url(self):
        """URL for the jwks info endpoint"""
        return self._jwks_url

    def get_handlers(self):
        """Return a dict with the auth handlers."""
        return self._handlers

    def get_rest_handlers(self):
        """Return a dict with the auth REST handlers."""
        return self._rest_handlers
