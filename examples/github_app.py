# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015 CERN.
#
# Invenio is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# Invenio is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Invenio; if not, write to the
# Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston,
# MA 02111-1307, USA.
#
# In applying this license, CERN does not
# waive the privileges and immunities granted to it by virtue of its status
# as an Intergovernmental Organization or submit itself to any jurisdiction.

r"""Minimal Flask application example for development with github handler.

Usage:

1. Register a gihub application with `Authorization callback URL` as
   `http://localhost:5000/oauth/authorized/github/`

2. Ensure you have ``github3.py`` package installed:

   .. code-block:: console

      cdvirtualenv src/invenio-oauthclient
      pip install -e .[github]

3. Grab the *Client ID* and *Client Secret* after registering the application
   and add them to your instance configuration as `consumer_key` and
   `consumer_secret`.

   .. code-block:: console

       $ export GITHUB_APP_CREDENTIALS_KEY=my_github_client_id
       $ export GITHUB_APP_CREDENTIALS_SECRET=my_github_client_secret

4. Create database and tables:

   .. code-block:: console

       $ cd examples
       $ flask -a github_app.py db init
       $ flask -a github_app.py db create

You can find the database in `examples/github_app.db`.

5. Run the development server:

   .. code-block:: console

       $ flask -a github_app.py run -p 5000 -h '0.0.0.0'

6. Open in a browser the page `http://0.0.0.0:5000/`.

   You will be redirected to github to authorize the application.

   Click on `Authorize application` and you will be redirected back to
   `http://localhost:5000/oauth/signup/github/`, where you will be able to
   finalize the local user registration, inserting email address.

   Insert e.g. `fuu@bar.it` as email address and send the form.

   Now, you will be again in homepage but this time it say: `hello fuu@bar.it`.

   You have completed the user registration.
"""

from __future__ import absolute_import, print_function

import os

from flask import Flask, redirect, url_for
from flask_babelex import Babel
from flask_cli import FlaskCLI
from flask_menu import Menu as FlaskMenu
from flask_oauthlib.client import OAuth as FlaskOAuth
from flask_security import current_user
from invenio_accounts import InvenioAccounts
from invenio_accounts.views import blueprint as blueprint_user
from invenio_db import InvenioDB

from invenio_oauthclient import InvenioOAuthClient
from invenio_oauthclient.contrib import github
from invenio_oauthclient.views.client import blueprint as blueprint_client
from invenio_oauthclient.views.settings import blueprint as blueprint_settings

# [ Configure application credentials ]
GITHUB_APP_CREDENTIALS = dict(
    consumer_key=os.environ.get('GITHUB_APP_CREDENTIALS_KEY'),
    consumer_secret=os.environ.get('GITHUB_APP_CREDENTIALS_SECRET'),
)

# Create Flask application
app = Flask(__name__)

app.config.update(
    SQLALCHEMY_DATABASE_URI=os.environ.get(
        'SQLALCHEMY_DATABASE_URI', 'sqlite:///github_app.db'
    ),
    OAUTHCLIENT_REMOTE_APPS=dict(
        github=github.REMOTE_APP,
    ),
    GITHUB_APP_CREDENTIALS=GITHUB_APP_CREDENTIALS,
    DEBUG=True,
    SECRET_KEY='TEST',
    SECURITY_PASSWORD_SALT='security-password-salt',
)

FlaskCLI(app)
Babel(app)
FlaskMenu(app)
InvenioDB(app)
InvenioAccounts(app)
FlaskOAuth(app)
InvenioOAuthClient(app)

app.register_blueprint(blueprint_user)
app.register_blueprint(blueprint_client)
app.register_blueprint(blueprint_settings)


@app.route('/')
def index():
    """Home page: try to print user email or redirect to login with github."""
    if not current_user.is_authenticated:
        return redirect(url_for("invenio_oauthclient.login",
                                remote_app='github'))
    return "hello {}".format(current_user.email)
