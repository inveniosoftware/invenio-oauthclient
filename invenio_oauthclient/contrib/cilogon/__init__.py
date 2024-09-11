""" Toolkit for creating remote apps that enable sign in/up with cilogon.  This was originally adapted from the keycloak plugin by
Robert Hancock of BNL. Anil Panta of JLAB  helped clean it up and added some code to convert CILogon groups to Invenio roles.

1. Register you invenio instance to cilogon via comanage registry and make sure it is configured appropriately,
   like in your comanage registry, set the callabck URI as
   "https://myinveniohost/oauth/authorized/cilogon/".
   Make sure to grab the *Client ID* and *Client Secret* . 
   Minimum scope/claim should be "openid", "email", "org.cilogon.userinfo", "profile".
   If you want allow certain group from cilogon to login you need to enable clain "isMemberOf".


2. Add the following items to your configuration (``invenio.cfg``).
   The ``CilogonSettingsHelper`` class can be used to help with setting up
   the configuration values:

.. code-block:: python

        from invenio_oauthclient.contrib import cilogon 

        helper = cilogon.CilogonSettingsHelper(
        title="CILOGON",
        description="CILOGON Comanage Registry",
        base_url="https://cilogon.org",
        precedence_mask={"email":True, "profile": {"username": False, "full_name": False, "affiliations": False}}
        )

        # precendence mask is added and email is set to true so that user's email is taken from cilogon not from user input.

        # create the configuration for cilogon
        # because the URLs usually follow a certain schema, the settings helper
        # can be used to more easily build the configuration values:
        OAUTHCLIENT_CILOGON_USER_INFO_URL = helper.user_info_url
        OAUTHCLIENT_CILOGON_JWKS_URL = helper.jwks_url
        OAUTHCLIENT_CILOGON_CONFIG_URL = helper.base_url+'/.well-known/openid-configuration'

        # CILOGON tokens, contains information about the target audience (AUD)
        # verification of the expected AUD value can be configured with:
        OAUTHCLIENT_CILOGON_VERIFY_AUD = True
        OAUTHCLIENT_CILOGON_AUD = "client audience"(same as client ID usually)

        # enable/disable checking if the JWT signature has expired
        OAUTHCLIENT_CILOGON_VERIFY_EXP = True

        # Cilogon role values (i.e. groups) that are allowed to be used
        OAUTHCLIENT_CILOGON_ALLOWED_ROLES = '["CO:COU:eic:members:all"]' 
        # error direct when user role/grup from cilogon doesn't match to allowed.
        OAUTHCLIENT_CILOGON_ROLES_ERROR_URL = "/"

        # if you want to allow users from any group without check of allowed roles
        # set the following to True (default is False)
        OAUTHCLIENT_CILOGON_ALLOW_ANY_ROLES=False

        # oidc claim name for LDAP Atrribute "isMemberOf". Default "isMemberOf")
        OAUTHCLIENT_CILOGON_GROUP_OIDC_CLAIM = "isMemberOf"

        # add CILOGON as external login providers to the dictionary of remote apps
        OAUTHCLIENT_REMOTE_APPS = dict(
        cilogon=helper.remote_app,
        )
        OAUTHCLIENT_REST_REMOTE_APPS = dict(
        cilogon=helper.remote_rest_app,
        )

        # set the following configuration to True to automatically use the
        # user's email address as account email
        USERPROFILES_EXTEND_SECURITY_FORMS = True

   By default, the title will be displayed as label for the login button,
    for example ``CILOGON``. The description will be
    displayed in the user account section.

3. Grab the *Client ID* and *Client Secret* from the 
   Comanage Registry and add them to your instance configuration (``invenio.cfg``):

   .. code-block:: python

        CILOGON_APP_CREDENTIALS = dict(
            consumer_key='<CLIENT ID>',
            consumer_secret='<CLIENT SECRET>',
        )

4. Now go to ``CFG_SITE_SECURE_URL/oauth/login/cilogon/`` (e.g.
   https://localhost:5000/oauth/login/cilogon/) and log in.

5. After authenticating successfully, you should see cilogon listed under
   Linked accounts: https://localhost:5000/account/settings/linkedaccounts/
"""



from .handlers import (
    disconnect_handler,
    disconnect_rest_handler,
    info_handler,
    setup_handler,
)
from .settings import CilogonSettingsHelper

__all__ = (
    "disconnect_handler",
    "disconnect_rest_handler",
    "info_handler",
    "setup_handler",
    "CilogonSettingsHelper",
)
