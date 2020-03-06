# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

r"""Minimal Flask application example for development with orcid handler.

SPHINX-START

1. Register an orcid application with `Authorization callback URL` as
   `http://localhost:5000/oauth/authorized/orcid/`

2. Install oauthclient:

   .. code-block:: console

      cdvirtualenv src/invenio-oauthclient
      pip install -e .[orcid]

3. Grab the *Client ID* and *Client Secret* after registering the application
   and add them to your instance configuration as `consumer_key` and
   `consumer_secret`.

   .. code-block:: console

       $ export ORCID_APP_CREDENTIALS_KEY=my_orcid_client_id
       $ export ORCID_APP_CREDENTIALS_SECRET=my_orcid_client_secret

4. Create database and tables:

   .. code-block:: console

       $ pip install -e .[all]
       $ cd examples
       $ export FLASK_APP=orcid_app.py
       $ ./app-setup.sh

You can find the database in `examples/orcid_app.db`.

5. Run the development server:

   .. code-block:: console

       $ flask -a orcid_app.py run -p 5000 -h '0.0.0.0'

6. Open in a browser the page `http://0.0.0.0:5000/orcid`.

   You will be redirected to orcid to authorize the application.

   Click on `Authorize application` and you will be redirected back to
   `http://0.0.0.0:5000/oauth/authorized/orcid/`, where you will be able to
   finalize the local user registration, inserting email address.

   Insert e.g. `fuu@bar.it` as email address and send the form.

   Now, you will be again in homepage but this time it say: `hello fuu@bar.it`.

   You have completed the user registration.

7. To be able to uninstall the example app:

   .. code-block:: console

       $ ./app-teardown.sh

SPHINX-END

"""

from __future__ import absolute_import, print_function

import os

from flask import Flask, redirect, url_for
from flask_babelex import Babel
from flask_login import current_user
from flask_menu import Menu as FlaskMenu
from invenio_accounts import InvenioAccounts
from invenio_accounts.views import blueprint as blueprint_user
from invenio_db import InvenioDB
from invenio_mail import InvenioMail as Mail
from invenio_userprofiles import InvenioUserProfiles
from invenio_userprofiles.views import \
    blueprint_api_init as blueprint_userprofile_api_init
from invenio_userprofiles.views import \
    blueprint_ui_init as blueprint_userprofile_ui_init

from invenio_oauthclient import InvenioOAuthClient
from invenio_oauthclient.contrib import orcid
from invenio_oauthclient.views.client import blueprint as blueprint_client
from invenio_oauthclient.views.settings import blueprint as blueprint_settings

from invenio_oauthclient._compat import monkey_patch_werkzeug  # noqa isort:skip
monkey_patch_werkzeug()  # noqa isort:skip

from flask_oauthlib.client import OAuth as FlaskOAuth  # noqa isort:skip

# [ Configure application credentials ]
ORCID_APP_CREDENTIALS = dict(
    consumer_key=os.environ.get('ORCID_APP_CREDENTIALS_KEY'),
    consumer_secret=os.environ.get('ORCID_APP_CREDENTIALS_SECRET'),
)

# Create Flask application
app = Flask(__name__)

app.config.update(
    SQLALCHEMY_ECHO=False,
    SQLALCHEMY_DATABASE_URI=os.environ.get(
        'SQLALCHEMY_DATABASE_URI', 'sqlite:///orcid_app.db'
    ),
    OAUTHCLIENT_REMOTE_APPS=dict(
        orcid=orcid.REMOTE_SANDBOX_APP,
    ),
    ORCID_APP_CREDENTIALS=ORCID_APP_CREDENTIALS,
    DEBUG=True,
    SECRET_KEY='TEST',
    SECURITY_PASSWORD_SALT='security-password-salt',
    SECURITY_LOGIN_WITHOUT_CONFIRMATION=False,
    USERPROFILES_EXTEND_SECURITY_FORMS=True,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
)

Babel(app)
FlaskMenu(app)
Mail(app)
InvenioDB(app)
InvenioAccounts(app)
InvenioUserProfiles(app)
FlaskOAuth(app)
InvenioOAuthClient(app)

app.register_blueprint(blueprint_user)
app.register_blueprint(blueprint_client)
app.register_blueprint(blueprint_settings)
app.register_blueprint(blueprint_userprofile_api_init)
app.register_blueprint(blueprint_userprofile_ui_init)


@app.route('/')
def index():
    """Homepage."""
    return 'Home page (without any restrictions)'


@app.route('/orcid')
def orcid():
    """Try to print user email or redirect to login with orcid."""
    if not current_user.is_authenticated:
        return redirect(url_for('invenio_oauthclient.login',
                                remote_app='orcid'))
    return 'hello {}'.format(current_user.email)
