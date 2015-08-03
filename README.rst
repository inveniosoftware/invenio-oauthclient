..
    This file is part of Invenio.
    Copyright (C) 2015 CERN.

    Invenio is free software; you can redistribute it
    and/or modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation; either version 2 of the
    License, or (at your option) any later version.

    Invenio is distributed in the hope that it will be
    useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Invenio; if not, write to the
    Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston,
    MA 02111-1307, USA.

    In applying this license, CERN does not
    waive the privileges and immunities granted to it by virtue of its status
    as an Intergovernmental Organization or submit itself to any jurisdiction.

=====================
 Invenio-OAuthClient
=====================

.. image:: https://img.shields.io/travis/inveniosoftware/invenio-oauthclient.svg
        :target: https://travis-ci.org/inveniosoftware/invenio-oauthclient

.. image:: https://img.shields.io/coveralls/inveniosoftware/invenio-oauthclient.svg
        :target: https://coveralls.io/r/inveniosoftware/invenio-oauthclient

.. image:: https://img.shields.io/github/tag/inveniosoftware/invenio-oauthclient.svg
        :target: https://github.com/inveniosoftware/invenio-oauthclient/releases

.. image:: https://img.shields.io/pypi/dm/invenio-oauthclient.svg
        :target: https://pypi.python.org/pypi/invenio-oauthclient

.. image:: https://img.shields.io/github/license/inveniosoftware/invenio-oauthclient.svg
        :target: https://github.com/inveniosoftware/invenio-oauthclient/blob/master/LICENSE


Invenio module that provides OAuth web authorization support.

OAuth client support is typically used to allow features such as social login
(e.g. Sign in with Twitter) and access to resources owner by a specific user
at a remote service. Both OAuth 1.0 and OAuth 2.0 are supported.

Features
========

The module contains:

- Views: OAuth login and authorized endpoints, linked account settings and
  sign-up handling.
- Client: A client to interact with remote applications.
- Contrib: Ready-to-use GitHub, ORCID, and CERN remote applications.
- Models: Persistence layer for OAuth access tokens including support for
  storing extra data together with a token.
- Handlers: Customizable handlers for deciding what happens when a user
  authorizes a request.
