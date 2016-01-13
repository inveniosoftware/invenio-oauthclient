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

Run example development server:

.. code-block:: console

   $ cd examples
   $ flask -a app.py shell

Create the database tables inside a SQLite database:

.. code-block:: console

   >> from invenio_db import db
   >> db.create_all()

You can find the database in `examples/app.db`.
"""

from __future__ import absolute_import, print_function

import os

from flask import Flask
from flask_babelex import Babel
from flask_cli import FlaskCLI
from flask_oauthlib.client import OAuth as FlaskOAuth
from invenio_accounts import InvenioAccounts
from invenio_admin import InvenioAdmin
from invenio_db import InvenioDB

from invenio_oauthclient import InvenioOAuthClient

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

FlaskCLI(app)
Babel(app)
InvenioDB(app)
InvenioAccounts(app)
FlaskOAuth(app)
InvenioOAuthClient(app)

InvenioAdmin(app, permission_factory=lambda x: x,
             view_class_factory=lambda x: x)
