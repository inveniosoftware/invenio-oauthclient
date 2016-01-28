# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015, 2016 CERN.
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

r"""Minimal Flask application example for development with CERN handler.

Usage:

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

       $ cd examples
       $ flask -a cern_app.py db init
       $ flask -a cern_app.py db create

You can find the database in `examples/cern_app.db`.

5. Create the key and the certificate in order to run a HTTPS server:

   .. code-block:: console

       $ openssl genrsa 1024 > ssl.key
       $ openssl req -new -x509 -nodes -sha1 -key ssl.key > ssl.crt

6. Run gunicorn server:

   .. code-block:: console

       $ gunicorn -b :5000 --certfile=ssl.crt --keyfile=ssl.key cern_app:app

7. Open in a browser the page `https://localhost:5000/`.

   You will be redirected to CERN to authorize the application.

   Click on `Grant` and you will be redirected back to
   `https://localhost:5000/oauth/authorized/cern/`

   Now, you will be again in homepage but this time it say:
   `hello youremail@cern.ch`.

   You have completed the user authorization.
"""

from __future__ import absolute_import, print_function

import copy
import redis
import os

from flask import Flask, redirect, url_for, session
from flask_babelex import Babel
from flask_cli import FlaskCLI
from flask_kvsession import KVSessionExtension
from flask_login import current_user
from flask_menu import Menu as FlaskMenu
from flask_oauthlib.client import OAuth as FlaskOAuth
from flask_principal import Identity, RoleNeed
from simplekv.memory.redisstore import RedisStore

from invenio_accounts import InvenioAccounts
from invenio_accounts.views import blueprint as blueprint_user
from invenio_db import InvenioDB
from invenio_oauthclient import InvenioOAuthClient
from invenio_oauthclient.contrib import cern
from invenio_oauthclient.signals import account_setup_received
from invenio_oauthclient.views.client import blueprint as blueprint_client
from invenio_oauthclient.views.settings import blueprint as blueprint_settings


# [ Configure application credentials ]
CERN_APP_CREDENTIALS = dict(
    consumer_key=os.environ.get('CERN_APP_CREDENTIALS_KEY'),
    consumer_secret=os.environ.get('CERN_APP_CREDENTIALS_SECRET'),
)

# Create Flask application
app = Flask(__name__)

app.config.update(
    SQLALCHEMY_DATABASE_URI=os.environ.get(
        'SQLALCHEMY_DATABASE_URI', 'sqlite:///cern_app.db'
    ),
    OAUTHCLIENT_REMOTE_APPS=dict(
        cern=cern.REMOTE_APP
    ),
    CERN_APP_CREDENTIALS=CERN_APP_CREDENTIALS,
    DEBUG=True,
    SECRET_KEY='TEST',
    SECURITY_PASSWORD_SALT='security-password-salt',
    SECURITY_SEND_REGISTER_EMAIL=False,
)

store = RedisStore(redis.StrictRedis())

FlaskCLI(app)
Babel(app)
FlaskMenu(app)
InvenioDB(app)
InvenioAccounts(app)
FlaskOAuth(app)
InvenioOAuthClient(app)
KVSessionExtension(store, app)

app.register_blueprint(blueprint_user)
app.register_blueprint(blueprint_client)
app.register_blueprint(blueprint_settings)
principal = app.extensions['security'].principal


# FIXME: This should probably go into invenio-accounts
@principal.identity_loader
def identity_loader_session():
    """Load the identity from the session."""
    try:
        identity = Identity(
            session['identity.id'], session['identity.auth_type'])
        identity.provides = session['identity.provides']
        return identity
    except KeyError:
        return None


@principal.identity_saver
def identity_saver_session(identity):
    """Save identity to the session."""
    session['identity.id'] = identity.id
    session['identity.auth_type'] = identity.auth_type
    session['identity.provides'] = identity.provides


@app.route('/')
def index():
    """Home page: try to print user email or redirect to login with cern."""
    if not current_user.is_authenticated:
        return redirect(url_for("invenio_oauthclient.login",
                                remote_app='cern'))
    return "hello {}".format(current_user.email)
