"""OAuthClient endpoint handlers for communication with Keycloak.

The handler functions provided in this module are tailored to communicate
with Keycloak using OpenID-Connect.
To use them, they must be referenced in a REMOTE_APP configuration dictionary,
e.g.:

.. code-block:: python

    KEYCLOAK_REMOTE_APP = {
        # ...

        "authorized_handler": "invenio_oauthclient.handlers"
                              ":authorized_signup_handler",
        "disconnect_handler": "invenio_keycloak.handlers"
                              ":disconnect_handler",
        "signup_handler": {
            "info": "invenio_keycloak.handlers:info_handler",
            "setup": "invenio_keycloak.handlers:setup_handler",
            "view": "invenio_oauthclient.handlers:signup_handler"
        },

        # ...
    }

"""

from .settings import KeycloakSettingsHelper
