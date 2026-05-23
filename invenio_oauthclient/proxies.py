# SPDX-FileCopyrightText: 2015-2018 CERN.
# SPDX-License-Identifier: MIT

"""Helper proxy to the state object."""

from flask import current_app
from werkzeug.local import LocalProxy

current_oauthclient = LocalProxy(lambda: current_app.extensions["invenio-oauthclient"])
