# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

r"""Minimal Flask application example for development with github handler.

SPHINX-START

1. Register a github application with `Authorization callback URL` as
   `http://localhost:5000/oauth/authorized/github/`

2. Ensure you have ``github3.py`` package installed:

   .. code-block:: console

       $ cdvirtualenv src/invenio-oauthclient
       $ pip install -e .[github]

3. Grab the *Client ID* and *Client Secret* after registering the application
   and add them to your instance configuration as `consumer_key` and
   `consumer_secret`.

   .. code-block:: console

       $ export GITHUB_APP_CREDENTIALS_KEY=my_github_client_id
       $ export GITHUB_APP_CREDENTIALS_SECRET=my_github_client_secret

4. Create database and tables:

   .. code-block:: console

       $ pip install -e .[all]
       $ cd examples
       $ export FLASK_APP=github_app_rest.py
       $ ./app-setup.sh

You can find the database in `examples/github_app.db`.

5. Run the development server:

   .. code-block:: console

       $ flask run -p 5000 -h '0.0.0.0'

6. Open in a browser the page `http://0.0.0.0:5000/github`.

   You will be redirected to github to authorize the application.

   Click on `Authorize application` and you will be redirected back to
   `http://localhost:5000/oauth/signup/github/`, where you will be able to
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
from invenio_mail import InvenioMail
from invenio_userprofiles import InvenioUserProfiles
from invenio_userprofiles.views import \
    blueprint_ui_init as blueprint_userprofile_init

from invenio_oauthclient import InvenioOAuthClientREST
from invenio_oauthclient.contrib import github
from invenio_oauthclient.views.client import rest_blueprint as blueprint_client

from invenio_oauthclient._compat import monkey_patch_werkzeug  # noqa isort:skip
monkey_patch_werkzeug()  # noqa isort:skip

from flask_oauthlib.client import OAuth as FlaskOAuth  # noqa isort:skip

# [ Configure application credentials ]
GITHUB_APP_CREDENTIALS = dict(
    consumer_key=os.environ.get('GITHUB_APP_CREDENTIALS_KEY'),
    consumer_secret=os.environ.get('GITHUB_APP_CREDENTIALS_SECRET'),
)

# Create Flask application
app = Flask(__name__)

app.config.update(
    SQLALCHEMY_DATABASE_URI=os.environ.get(
        'SQLALCHEMY_DATABASE_URI', 'sqlite:///github_app_rest.db'
    ),
    OAUTHCLIENT_REST_REMOTE_APPS=dict(
        github=github.REMOTE_REST_APP,
    ),
    GITHUB_APP_CREDENTIALS=GITHUB_APP_CREDENTIALS,
    DEBUG=True,
    SECRET_KEY='TEST',
    SQLALCHEMY_ECHO=False,
    SECURITY_PASSWORD_SALT='security-password-salt',
    MAIL_SUPPRESS_SEND=True,
    TESTING=True,
    USERPROFILES_EXTEND_SECURITY_FORMS=True,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
)

Babel(app)
FlaskMenu(app)
InvenioDB(app)
InvenioAccounts(app)
InvenioUserProfiles(app)
FlaskOAuth(app)
InvenioOAuthClientREST(app)
InvenioMail(app)

app.register_blueprint(blueprint_user)
app.register_blueprint(blueprint_client)
app.register_blueprint(blueprint_userprofile_init)


@app.route('/')
def index():
    """Homepage."""
    return 'Home page (without any restrictions)'


@app.route('/github')
def github():
    """Try to print user email or redirect to login with github."""
    if not current_user.is_authenticated:
        return redirect(url_for('invenio_oauthclient.rest_login',
                                remote_app='github'))
    return 'hello {}'.format(current_user.email)
