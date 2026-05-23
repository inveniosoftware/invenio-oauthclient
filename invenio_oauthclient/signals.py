# SPDX-FileCopyrightText: 2015-2018 CERN.
# SPDX-License-Identifier: MIT

"""Signals used together with various handlers."""

from blinker import Namespace

_signals = Namespace()

account_info_received = _signals.signal("oauthclient-account-info-received")
"""Signal is sent after account info handler response.

Example subscriber:

.. code-block:: python

    from invenio_oauthclient.signals import account_info_received

    # During overlay initialization.
    @account_info_received.connect
    def load_extra_information(remote, token=None, response=None,
                               account_info=None):
        response = remote.get('https://example.org/api/resource')
        # process response

"""

account_setup_received = _signals.signal("oauthclient-account-setup-received")
"""Signal is sent after account info handler response.

Example subscriber:

.. code-block:: python

    from invenio_oauthclient.signals import account_setup_received

    # During overlay initialization.
    @account_setup_received.connect
    def load_extra_information(remote, token=None, response=None,
                               account_setup=None):
        response = remote.get('https://example.org/api/resource')
        # process response

"""


account_setup_committed = _signals.signal("oauthclient-account-setup-committed")
"""Signal is sent after account setup has been committed to database.

Example subscriber:

.. code-block:: python

    from invenio_oauthclient.signals import account_setup_committed

    # During overlay initialization.
    @account_setup_committed.connect
    def fetch_info(remote):
        response = remote.get('https://example.org/api/resource')
        # process response

"""
