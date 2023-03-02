..
    This file is part of Invenio.
    Copyright (C) 2015-2022 CERN.

    Invenio is free software; you can redistribute it and/or modify it
    under the terms of the MIT License; see LICENSE file for more details.

Changes
=======

Version 2.2.0 (released 2023-03-02)

- remove deprecated flask_babelex dependency and imports
- upgrade invenio-i18n

Version 2.1.0 (released 2022-12-19)

- Increase minimal Python version to 3.7.
- Deprecate the old CERN OAuth contrib.
- Allow specific sign-up settings per OAuth app.
- Add signup `info_serialize` handler to allow serializing the
  user info response.

Version 2.0.1 (released 2022-07-01)

- Remove Babel extension.
- Add german translations.
- Fix checkbox label display inside loops.

Version 2.0.0 (released 2022-05-24)

- Moved UserIdentity to Invenio-Accounts.
- Fixes to signup error handling.

Version 1.5.4 (released 2021-10-18)

- Add OpenAIRE AAI contrib.

Version 1.5.3 (released 2021-10-18)

- Unpin Flask.

Version 1.5.2 (released 2021-07-12)

- Add german translations

Version 1.5.1 (released 2021-05-26)

- Allow to automatically redirect to the external login provider under
  certain conditions.
- Disable the possibility to disconnect the last external account to
  always have at least one external account connected (when configured).
- Make registration form customizable to allow adding extra form fields
  when the user login the first time.
- CERN contribs: fix bug that will execute login/logout signal for CERN
  contribs even if the user logged in a different way.

Version 1.5.0 (released 2021-05-07)

- Keycloak: refactor settings helper to allow multiple instances of
  configured keycloak authentication providers at the same time
- OAuth: create a new settings helper to set up in an easier way a OAuth
  authentication provider.

Version 1.4.4 (released 2021-02-05)

- CERN OpenID: make /userinfo endpoint and JWT token decode parameters
  configurable

Version 1.4.3 (released 2021-02-05)

- REST auth: add exception logger

Version 1.4.2 (released 2021-01-15)

- Add Keycloak contrib.

Version 1.4.1 (released 2021-01-04)

- Use `invenio-theme` THEME_ICONS config
- Fix disconnect button styling

Version 1.4.0 (released 2020-12-09)

- Use centrally managed test dependencies.
- Add CERN OpenID contrib.
- Migrate CI to GitHub Actions.
- Several UI styling fixes.

Version 1.4.0a1 (released 2020-06-22)

- Integrates Semantic-UI templates.

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
