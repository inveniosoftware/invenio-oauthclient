# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

r"""Minimal Flask application example for development with CERN handler.

SPHINX-START

1. Register a CERN application in
   `https://sso-management.web.cern.ch/OAuth/RegisterOAuthClient.aspx` with
   `redirect_uri` as
   `https://localhost:5000/oauth/authorized/cern/` and filling all the other
   fields:


2. Ensure you have ``gunicorn`` package installed:

   .. code-block:: console

      cdvirtualenv src/invenio-oauthclient
      pip install -e gunicorn


3. Ensure you have ``openssl`` installed in your system (Most of the Linux
   distributions has it by default.).


3. Grab the *client_id* and *secret_uri* after registering the application
   and add them to your instance configuration as `consumer_key` and
   `consumer_secret`.

   .. code-block:: console

       $ export CERN_APP_CREDENTIALS_KEY=my_cern_client_id
       $ export CERN_APP_CREDENTIALS_SECRET=my_cern_secret_uri

4. Create database and tables:

   .. code-block:: console

       $ pip install -e .[all]
       $ cd examples
       $ export FLASK_APP=cern_app_rest.py
       $ ./app-setup.sh

You can find the database in `examples/cern_app.db`.

5. Create the key and the certificate in order to run a HTTPS server:

   .. code-block:: console

       $ openssl genrsa 1024 > ssl.key
       $ openssl req -new -x509 -nodes -sha1 -key ssl.key > ssl.crt

6. Run gunicorn server:

   .. code-block:: console

       $ gunicorn -b :5000 --certfile=ssl.crt --keyfile=ssl.key cern_app:app

7. Open in a browser the page `https://localhost:5000/cern`.

   You will be redirected to CERN to authorize the application.

   Click on `Grant` and you will be redirected back to
   `https://localhost:5000/oauth/authorized/cern/`

   Now, you will be again in homepage but this time it say:
   `hello youremail@cern.ch`.

   You have completed the user authorization.

8. To be able to uninstall the example app:

   .. code-block:: console

       $ ./app-teardown.sh

SPHINX-END

"""

import os

from flask import Flask, redirect, url_for
from flask_babelex import Babel
from flask_login import current_user
from flask_menu import Menu as FlaskMenu
from invenio_accounts import InvenioAccounts
from invenio_accounts.views import blueprint as blueprint_user
from invenio_db import InvenioDB

from invenio_oauthclient import InvenioOAuthClientREST
from invenio_oauthclient.contrib import cern
from invenio_oauthclient.views.client import rest_blueprint as blueprint_client

from invenio_oauthclient._compat import monkey_patch_werkzeug  # noqa isort:skip
monkey_patch_werkzeug()  # noqa isort:skip

from flask_oauthlib.client import OAuth as FlaskOAuth  # noqa isort:skip

# [ Configure application credentials ]
CERN_APP_CREDENTIALS = dict(
    consumer_key=os.environ.get('CERN_APP_CREDENTIALS_KEY'),
    consumer_secret=os.environ.get('CERN_APP_CREDENTIALS_SECRET'),
)

# Create Flask application
app = Flask(__name__)

app.config.update(
    SQLALCHEMY_DATABASE_URI=os.environ.get(
        'SQLALCHEMY_DATABASE_URI', 'sqlite:///cern_app_rest.db'
    ),
    OAUTHCLIENT_REST_REMOTE_APPS=dict(
        cern=cern.REMOTE_REST_APP
    ),
    CERN_APP_CREDENTIALS=CERN_APP_CREDENTIALS,
    DEBUG=True,
    SECRET_KEY='TEST',
    SECURITY_PASSWORD_SALT='security-password-salt',
    SECURITY_SEND_REGISTER_EMAIL=False,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    APP_THEME=['semantic-ui'],
    THEME_ICONS={
      'semantic-ui': dict(
            link='linkify icon'
      )
    }
)

Babel(app)
FlaskMenu(app)
InvenioDB(app)
InvenioAccounts(app)
FlaskOAuth(app)
InvenioOAuthClientREST(app)

app.register_blueprint(blueprint_user)
app.register_blueprint(blueprint_client)
principal = app.extensions['security'].principal


@app.route('/')
def index():
    """Homepage."""
    return 'Home page (without any restrictions)'


@app.route('/cern')
def cern():
    """Home page: try to print user email or redirect to login with cern."""
    if not current_user.is_authenticated:
        return redirect(url_for('invenio_oauthclient.rest_login',
                                remote_app='cern'))

    return 'hello {}'.format(current_user.email)
