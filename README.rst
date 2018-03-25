..
    This file is part of Invenio.
    Copyright (C) 2015-2018 CERN.

    Invenio is free software; you can redistribute it and/or modify it
    under the terms of the MIT License; see LICENSE file for more details.

=====================
 Invenio-OAuthClient
=====================

.. image:: https://img.shields.io/github/license/inveniosoftware/invenio-oauthclient.svg
        :target: https://github.com/inveniosoftware/invenio-oauthclient/blob/master/LICENSE

.. image:: https://img.shields.io/travis/inveniosoftware/invenio-oauthclient.svg
        :target: https://travis-ci.org/inveniosoftware/invenio-oauthclient

.. image:: https://img.shields.io/coveralls/inveniosoftware/invenio-oauthclient.svg
        :target: https://coveralls.io/r/inveniosoftware/invenio-oauthclient

.. image:: https://img.shields.io/pypi/v/invenio-oauthclient.svg
        :target: https://pypi.org/pypi/invenio-oauthclient


Invenio module that provides OAuth web authorization support.

OAuth client support is typically used to allow features such as social login
(e.g. Sign in with Twitter) and access to resources owned by a specific user
at a remote service. Both OAuth 1.0 and OAuth 2.0 are supported.

Features:

- Views: OAuth login and authorized endpoints, linked account settings and
  sign-up handling.
- Client: A client to interact with remote applications.
- Contrib: Ready-to-use GitHub, ORCID, and CERN remote applications.
- Models: Persistence layer for OAuth access tokens including support for
  storing extra data together with a token.
- Handlers: Customizable handlers for deciding what happens when a user
  authorizes a request.

Further documentation is available on
https://invenio-oauthclient.readthedocs.io/
