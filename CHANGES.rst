..
    This file is part of Invenio.
    Copyright (C) 2015-2023 CERN.
    Copyright (C) 2024 Graz University of Technology.

    Invenio is free software; you can redistribute it and/or modify it
    under the terms of the MIT License; see LICENSE file for more details.

Changes
=======

Version v5.2.0 (released 2025-07-17)

- i18n: pulled translations
- i18n: push translations
- fix app allowed hosts (#356)
- fix: pkg_resources DeprecationWarning
- fix: setuptools require underscores instead of dashes
- i18n: removed deprecated messages
- fix: i18n-unrelated keycloak test missing app fixture
- Fix: i18n: added gettext to places where it was missing
- inline(docs): fix

Version 5.1.0 (released 2024-12-12)

- fix: DeprecationWarning:
- fix: TypeError
- setup: move to flask-oauthlib-invenio

Version 5.0.0 (released 2024-12-06)

- fix: sqlalchemy.exc.ArgumentError:
- global: use invenio_base.jws not itsdangerous
- tests: apply changes for sqlalchemy>=2.0
- setup: bump major dependencies

Version 4.1.3 (release 2024-12-03)

- utils: improve and fix creation/update of groups

Version 4.1.2 (release 2024-11-30)

- setup: pin dependencies
- ci: use reusable workflow when publishing

Version 4.1.0 (released 2024-11-07)

- handlers: add basic error handling for roles creation
- fix: compat for flask-oauthlib

Version 4.1.0 (released 2024-11-07)

- setup: remove upper pins oauthlib,requests-oauthlib
- global: jws use from invenio-base
- fix: for flask >= 3.0.0 compatibility

Version 4.0.2 (released 2024-09-17)

- fix: inverted check for visible remote apps

Version 4.0.1 (released 2024-09-11)

- i18n: push translations
- keycloak: add `legacy_url_path` parameter to the `KeycloakSettingsHelper`
- global: explicitly set and use `hide` attribute for config

Version 4.0.0 (released 2024-03-23)

- fix: before_app_first_request deprecation
- installation: remove invenio-admin
- installation: switch to uritemplate to avoid dependency conflicts

Version 3.5.1 (released 2023-08-30)

- orcid: show registration form errors on validations errors

Version 3.5.0 (released 2023-08-30)

- oauth: handle properly workflow when user is not yet confirmed and auto-confirm is
  disabled for remote

Version 3.4.1 (released 2023-08-16)

- utils: removed creation of UserNeed email

Version 3.4.0 (released 2023-08-09)

- groups: make groups fetching async
- load user and role needs on identity loaded

Version 3.3.0 (released 2023-07-24)

- settings: Improve layout for a11y

Version 3.2.0 (released 2023-07-24)

- authorize: refactor authorize/signup handlers
- update translations

Version 3.1.2 (released 2023-06-23)

- client: preserve "next" URL param on login redirection

Version 3.1.1 (released 2023-06-21)

- client: fix user confirmation

Version 3.1.0 (released 2023-06-20)

- client: add provider's logout url

Version 3.0.0 (released 2023-06-14)

- base client: add group handler

Version 2.3.0 (released 2023-03-13)

- OpenAIRE AAI sandbox remote moved to Keycloak.
- Keycloak settings helper accept configurable scopes for token request.

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
