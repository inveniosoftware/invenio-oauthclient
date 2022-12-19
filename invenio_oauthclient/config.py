# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2018 CERN.
# Copyright (C)      2021 TU Wien.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Configuration variables for defining remote applications.

================================ ==============================================
`OAUTHCLIENT_REMOTE_APPS`        Dictionary of remote applications. See example
                                 below. **Default:** ``{}``.
`OAUTHCLIENT_SESSION_KEY_PREFIX` Prefix for the session key used to store the
                                 an access token. **Default:** ``oauth_token``.
`OAUTHCLIENT_STATE_EXPIRES`      Number of seconds after which the state token
                                 expires. Defaults to 300 seconds.
`OAUTHCLIENT_REMOTE_APP`         Replaces the default remote application class.
================================ ==============================================

Each remote application must be defined in the ``OAUTHCLIENT_REMOTE_APPS``
dictionary, where the keys are the application names and the values the
configuration parameters for the application.

.. code-block:: python

    OAUTHCLIENT_REMOTE_APPS = dict(
        myapp=dict(
            # configuration values for myapp ...
        ),
    )

The application name is used in the login, authorized, sign-up and disconnect
endpoints:

- Login endpoint: ``/oauth/login/<REMOTE APP>/``.
- Authorized endpoint: ``/oauth/authorized/<REMOTE APP>/``.
- Disconnect endpoint: ``/oauth/disconnect/<REMOTE APP>/``.
- Sign up endpoint: ``/oauth/login/<REMOTE APP>/``.


Remote application
^^^^^^^^^^^^^^^^^^
Configuration of a single remote application is a dictionary with the following
keys:

- ``title`` - Title of remote application. Displayed to end-users under Account
  > Linked accounts.
- ``description`` - Short description of remote application. Displayed to
  end-users under Account > Linked accounts.
- ``icon`` - CSS class for icon of service (e.g. ``fa fa-github`` for using the
  Font-Awesome GitHub icon). Displayed to end-users.
- ``params`` - Flask-OAuthlib remote application parameters..
- ``authorized_handler`` - Import path to authorized callback handler.
- ``disconnect_handler`` - Import path to disconnect callback handler.
- ``signup_handler`` - A dictionary of import path to sign up callback handler.
- ``precedence_mask`` - A mask determining which user info values should
  override user input during sign-up.

.. code-block:: python

    OAUTHCLIENT_REMOTE_APPS = dict(
        myapp=dict(
            title='...',
            description='...',
            icon='...',
            authorized_handler="...",
            disconnect_handler="...",
            signup_handler=dict(
                info="...",
                setup="...",
                view="...",
            ),
            precedence_mask=dict(
                email=True
            ),
            signup_options=dict(
                auto_confirm=True,
                send_register_msg=False,
            ),
            params=dict(...),
            )
        )
    )

Note on the ``precedence_mask``:

This mask is used during sign-up of new users via external OAuth
providers, to determine for which of the new user's properties the
`user_info` given by the OAuth provider must take precedence over
any user input.

Properties marked with `False` in the precedence mask will be used
as specified by the user.
Any properties marked with `True` (or not appearing) in the precedence
mask will be taken from the OAuth service's `user_info` dictionary,
overriding any potential user input from registration forms.
If a property is missing from the `user_info` dictionary, the
configured value in the precedence mask is irrelevant.

For instance, if the following user info were given by the OAuth
remote app during signup, and the precedence mask configured as
follows:

.. code-block:: python

    # user_info from the oauth remote app
    {
        "email": "user@inveniosoftware.org",
        "password": "somepassword",
        "profile": {
            "username": "test-user",
            "full_name": "Test User",
        }
    }

    # precedence_mask
    {
        "email": True,
        "profile": {
            "username": True,
            "full_name": False,
        }
    }

Then, the values for `email` and `profile.username` from the
`user_info` would be overriding any user input from the registration
form.
All other values would be used as provided by the user in the form.

WARNING: Allowing users to specify their email address arbitrarily
(`precedence_mask["email"] = False`) during sign-up may have severe
security implications, as the linking of external accounts with
accounts in Invenio is done by matching email addresses!

Note on the ``signup_options``:

This parameter accepts a dictionary with `auto_confirm` and `send_register_msg`
boolean values.

When `auto_confirm` is set to `True` (default), the user, after the first login, will
be automatically confirmed and will not receive an e-mail with a link to confirm
the account. This is the common behaviour normally expected when authentication
happens via an external provider. The only exception is the ORCID contribution,
given that the e-mail is input by the user (and therefor should be confirmed).

The `send_register_msg` allows to set if the welcome e-mail, after the first login,
should be sent. Normally, it should be disabled when using OAuth. `False` by
default.


Remote REST application
^^^^^^^^^^^^^^^^^^^^^^^
Configuration of a single remote REST application is a dictionary with the
same keys as Remote application in addition to:

- ``response_handler`` - Import path to response callback handler.
- ``authorized_redirect_url`` - URL path to redirect your SPA when login was
  successfull.
- ``disconnect_redirect_url`` - URL path to redirect your SPA after logging
  out.
- ``signup_redirect_url`` - URL path to redirect your SPA to sign up a user.
- ``error_redirect_url`` - URL path to redirect your SPA when an error occurred


.. code-block:: python

    OAUTHCLIENT_REMOTE_APPS = dict(
        myapp=dict(
            title='...',
            description='...',
            icon='...',
            authorized_handler="...",
            disconnect_handler="...",
            signup_handler=dict(
                info="...",
                info_serializer="...",
                setup="...",
                view="...",
            ),
            response_handler=("..."),
            authorized_redirect_url="...",
            disconnect_redirect_url="...",
            signup_redirect_url="...",
            error_redirect_url="...",
            precedence_mask=dict(...),
            params=dict(...),
            )
        )
    )


Flask-OAuthlib parameters
^^^^^^^^^^^^^^^^^^^^^^^^^
The Flask-OAuthlib parameters defines the remote application OAuth endpoints as
well as the client id and secret. Full description of these parameters are
given in the `Flask-OAuthlib documentation
<https://flask-oauthlib.readthedocs.io/en/latest/client.html>`_.

Normally you will have to browse the remote application's API documentation to
find which URLs and scopes to use.

Below is an example for GitHub:

.. code-block:: python

    OAUTHCLIENT_REMOTE_APPS = dict(
        github=dict(
            # ...
            params=dict(
                request_token_params={'scope': 'user:email'},
                base_url='https://api.github.com/',
                request_token_url=None,
                access_token_url="https://github.com/login/oauth/access_token",
                access_token_method='POST',
                authorize_url="https://github.com/login/oauth/authorize",
                app_key="GITHUB_APP_CREDENTIALS",
            )
        )
    )

    GITHUB_APP_CREDENTIALS=dict(
        consumer_key="changeme"
        consumer_secret="changeme"
    )

The ``app_key`` parameter allows you to put your sensitive client id and secret
in your instance configuration (``var/invenio.base-instance/invenio.cfg``).

Handlers
^^^^^^^^
Handlers allow customizing oauthclient endpoints for each remote
application:

- Authorized endpoint: ``/oauth/authorized/<REMOTE APP>/``.
- Disconnect endpoint: ``/oauth/disconnect/<REMOTE APP>/``.
- Sign up endpoint: ``/oauth/login/<REMOTE APP>/``.

By default only authorized and disconnect handlers are required, and Invenio
provide default implementation that stores the access token in the user session
as well as to the database if the user is authenticated:


.. code-block:: python

    OAUTHCLIENT_REMOTE_APPS = dict(
        myapp=dict(
            # ...
            authorized_handler="invenio_oauthclient.handlers"
                       ":authorized_default_handler",
            disconnect_handler="invenio_oauthclient.handlers"
                       ":disconnect_handler",
            )
            # ...
        )
    )

If you want to provide sign in/up functionality using oauthclient, Invenio
comes with a default handler that will try to find a matching local user for
a given authorize request.

.. code-block:: python

    OAUTHCLIENT_REMOTE_APPS = dict(
        orcid=dict(
            # ...
            authorized_handler="invenio_oauthclient.handlers"
                       ":authorized_signup_handler",
            disconnect_handler="invenio_oauthclient.handlers"
                       ":disconnect_handler",
            )
            signup_handler=dict(
                info="invenio_oauthclient.contrib.orcid:account_info",
                info_serializer="invenio_oauthclient.contrib.orcid:account_info_serializer",
                setup="invenio_oauthclient.contrib.orcid:account_setup",
                view="invenio_oauthclient.handlers:signup_handler",
            ),
            # ...
        )
    )

Custom remote application
^^^^^^^^^^^^^^^^^^^^^^^^^

Some OAuth services require a specific handling of OAuth requests. If the
standard flask-oauthlib.client.OAuthRemoteApp does not support it, it is
possible to replace the standard OAuthRemoteApp for all remote application
by referring to the custom class with the configuration variable
``OAUTHCLIENT_REMOTE_APP`` or for only one remote application by
setting ``remote_app`` in your remote application configuration.

.. code-block:: python

    class CustomOAuthRemoteApp(OAuthRemoteApp):
        pass

    app.config.update(
        OAUTHCLIENT_REMOTE_APP=
            'myproject.mymodule:CustomOAuthRemoteApp'
    )

    # OR

    app.config.update(
        OAUTHCLIENT_REMOTE_APPS=dict(
            custom_app=dict(
                # ...
                remote_app=
                    'myproject.mymodule:CustomOAuthRemoteApp'
            )
        )
    )

"""

from invenio_oauthclient.utils import _create_registrationform

from .views.client import auto_redirect_login

OAUTHCLIENT_REMOTE_APPS = {}
"""Configuration of remote applications."""

OAUTHCLIENT_SESSION_KEY_PREFIX = "oauth_token"
"""Session key prefix used when storing the access token for a remote app."""

OAUTHCLIENT_STATE_EXPIRES = 300
"""Number of seconds after which the state token expires."""

OAUTHCLIENT_STATE_ENABLED = True
"""Internal variable used to disable state validation during tests."""

OAUTHCLIENT_SIGNUP_FORM = _create_registrationform
"""Function called to render the sign up form after authorization succeeded."""

OAUTHCLIENT_SIGNUP_TEMPLATE = "invenio_oauthclient/signup.html"
"""Template for the signup page."""

OAUTHCLIENT_REST_REMOTE_APPS = {}
"""Configuration of remote rest applications."""

OAUTHCLIENT_REST_DEFAULT_ERROR_REDIRECT_URL = "/"
"""Configuration of default error redirect URL."""

OAUTHCLIENT_REST_DEFAULT_RESPONSE_HANDLER = None
"""Default REST response handler."""

OAUTHCLIENT_AUTO_REDIRECT_TO_EXTERNAL_LOGIN = False
"""Redirect to the only external login service under specific conditions.

If this option is enabled and there is exactly one external authentication
service enabled (i.e. one OAuthClient remote app is configured, and local
login is disabled), the login view function will automatically redirect to
this external authentication service.
"""
