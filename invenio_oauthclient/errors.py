# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Module level errors."""

# Imported here for backward compatibility after moving UserIdentity to
# Invenio-Accounts.
from invenio_accounts.errors import AlreadyLinkedError


class OAuthError(Exception):
    """Base class for OAuth exceptions."""

    def __init__(self, message, remote):
        """Initialize exception.

        :param message: Error message.
        :param message: Remote application.
        """
        self.message = message
        self.remote = remote


class OAuthResponseError(OAuthError):
    """Define response exception during OAuth process."""

    def __init__(self, message, remote, response):
        """Initialize exception.

        :param message: Error message.
        :param remote: Remote application.
        :param response: OAuth response object.
        """
        super().__init__(message, remote)
        self.response = response


class OAuthRejectedRequestError(OAuthResponseError):
    """Define exception for rejected response during OAuth process."""


class OAuthClientError(OAuthResponseError):
    """Define OAuth client exception.

    Client errors happens when the client (i.e. Invenio) creates an invalid
    request.
    """

    def __init__(self, message, remote, response):
        """Initialize exception.

        :param message: Error message.
        :param remote: Remote application.
        :param response: OAuth response object. Used to extract ``error``,
                         ``error_uri`` and ``error_description``.
        """
        # Only OAuth2 specifies how to send error messages
        self.code = response["error"]
        self.uri = response.get("error_uri", None)
        self.description = response.get("error_description", None)
        super().__init__(self.description or message, remote, response)


class OAuthCERNRejectedAccountError(OAuthResponseError):
    """Define exception for not allowed cern accounts."""


class OAuthKeycloakUserInfoError(OAuthResponseError):
    """Define exception for problems while fetching user info from Keycloak."""


class OAuthClientUnAuthorized(Exception):
    """Define exception for unauthorized user."""


class OAuthClientAlreadyAuthorized(Exception):
    """Define exception for user already authorized."""


class OAuthClientTokenNotFound(Exception):
    """Define exception for oauth token not found."""


class OAuthClientUserNotRegistered(Exception):
    """Define exception for user not registered."""


class OAuthClientTokenNotSet(Exception):
    """Define exception for oauth token not set."""


class OAuthClientMustRedirectSignup(Exception):
    """Define exception for forcing redirection to signup view."""


class OAuthClientMustRedirectLogin(Exception):
    """Define exception for forcing redirection to login view."""


class OAuthRemoteNotFound(Exception):
    """Define exception for remote app not found."""


class OAuthClientUserRequiresConfirmation(Exception):
    """User requires to confirm their email."""

    def __init__(self, user, *args, **kwargs):
        """Initialize exception.

        :param user: User object whose email requires confirmation.
        """
        self.user = user
        super().__init__(*args, **kwargs)
