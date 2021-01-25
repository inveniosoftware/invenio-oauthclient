..
    This file is part of Invenio.
    Copyright (C) 2015-2020 CERN.

    Invenio is free software; you can redistribute it and/or modify it
    under the terms of the MIT License; see LICENSE file for more details.

Changes
=======

Version 1.3.6 (released 2021-01-25)

- REST auth: add exception logger

Version 1.3.5 (released 2020-10-30)

- CERN Open ID: handle login via User Token

Version 1.3.4 (released 2020-10-04)

- CERN providers: clear user roles on logout

Version 1.3.3 (released 2020-08-31)

- Add CERN OpenID OAuth provider.

Version 1.3.2 (released 2020-06-25)

- Fixes orcid access token url.

Version 1.3.1 (released 2020-06-03)

- Exports rest handlers.

Version 1.3.0 (released 2020-05-15)

- Introduce `InvenioOAuthClientREST` extension.
- The module can be used as a full REST OAuth service. For example, from
  an SPA application. All responses are being handled by redirecting to
  user's configured endpoints.
- The new configuration variable `OAUTHCLIENT_REST_REMOTE_APPS` defines the
  registered applications that are using the REST OAuth workflow.

Version 1.2.1 (released 2020-04-17)

- Fix args from redirect target' encoding

Version 1.2.0 (released 2020-03-13)

- Centrally manage Flask dependency by invenio-base
- Drop support for Python 2.7

Version 1.1.3 (released 2019-07-29)

- Remove deprecated warnings from 3rd party modules
- Fix setup file extension
- Fix missing args from redirect target

Version 1.1.2 (released 2019-02-01)

- CERN OAuth: fix logout url

Version 1.1.1 (released 2019-01-22)

- CERN OAuth: filter authentication by IdentityClass
- Pin oauthlib lower than 3.0

Version 1.1.0 (released 2018-12-14)

Version 1.0.0 (released 2018-03-23)

- Initial public release.
