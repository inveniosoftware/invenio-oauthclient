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

"""Minimal Flask application example for development.

Run Redis server on background.

Install requirements:

.. code-block:: console

   $ pip install -e .[all]
   $ cd examples
   $ export FLASK_APP=app.py
   $ ./app-setup.sh

Run the server:

.. code-block:: console

   $ flask run --debugger -p 5000

To be able to uninstall the example app:

.. code-block:: console

   $ ./app-teardown.sh
"""

from __future__ import absolute_import, print_function

import os

from flask import Flask
from flask_babelex import Babel
from flask_menu import Menu
from flask_oauthlib.client import OAuth as FlaskOAuth
from invenio_accounts import InvenioAccounts
from invenio_accounts.views import blueprint as blueprint_accounts
from invenio_admin import InvenioAdmin
from invenio_db import InvenioDB

from invenio_oauthclient import InvenioOAuthClient
from invenio_oauthclient.views.client import blueprint as blueprint_client
from invenio_oauthclient.views.settings import blueprint as blueprint_settings

# Create Flask application
app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'SQLALCHEMY_DATABASE_URI', 'sqlite:///app.db'
)

app.config.update(
    ACCOUNTS_USE_CELERY=False,
    CELERY_ALWAYS_EAGER=True,
    CELERY_CACHE_BACKEND='memory',
    CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
    CELERY_RESULT_BACKEND='cache',
    MAIL_SUPPRESS_SEND=True,
    SECRET_KEY='CHANGE_ME',
    SECURITY_PASSWORD_SALT='CHANGE_ME_ALSO',
)

Babel(app)
Menu(app)
InvenioDB(app)
InvenioAccounts(app)
FlaskOAuth(app)
InvenioOAuthClient(app)

app.register_blueprint(blueprint_client)
app.register_blueprint(blueprint_settings)
app.register_blueprint(blueprint_accounts)

InvenioAdmin(app, permission_factory=lambda x: x,
             view_class_factory=lambda x: x)
