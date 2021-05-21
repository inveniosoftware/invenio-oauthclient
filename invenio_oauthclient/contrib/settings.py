# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Common OAuth configuration helper."""

from werkzeug import cached_property


class OAuthSettingsHelper:
    """Helper for creating REMOTE_APP configuration dictionaries for OAuth."""

    _remote_app = None
    _remote_rest_app = None

    def __init__(
        self,
        title,
        description,
        base_url,
        app_key,
        icon=None,
        access_token_url=None,
        authorize_url=None,
        access_token_method="POST",
        request_token_params=None,
        request_token_url=None,
        precedence_mask=None,
        **kwargs,
    ):
        """The constructor."""
        self.base_url = "{}/".format(base_url.rstrip("/"))  # add leading `/`
        icon = icon or ""
        request_token_params = request_token_params or {"scope": ""}
        access_token_url = access_token_url or f"{self.base_url}oauth2/token"
        authorize_url = authorize_url or f"{self.base_url}oauth2/authorize"
        precedence_mask = precedence_mask or {
            "email": True,
            "password": False,
            "profile": {
                "username": False,
                "full_name": False,
            },
        }

        self.base_app = dict(
            title=title,
            description=description,
            icon=icon,
            precedence_mask=precedence_mask,
            params=dict(
                base_url=self.base_url,
                request_token_params=request_token_params,
                request_token_url=request_token_url,
                access_token_url=access_token_url,
                access_token_method=access_token_method,
                authorize_url=authorize_url,
                app_key=app_key,
                **kwargs,
            ),
        )

    def get_handlers(self):
        """Return a dict with the auth handlers.

        It should return a dict in this format:
        dict(
            authorized_handler='path_to_method_authorized_signup_handler',
            disconnect_handler='path_to_method_authorized_disconnect_handler',
        signup_handler=dict(
            info='path_to_method_account_info',
            setup='path_to_method_account_setup',
            view='path_to_method_signup_form_handler',
        )
        """
        raise NotImplementedError

    @cached_property
    def remote_app(self):
        """Create a KEYCLOAK_REMOTE_APP using the given base URL and realm."""
        self._remote_app = dict(self.base_app)
        self._remote_app.update(self.get_handlers())
        return self._remote_app

    def get_rest_handlers(self):
        """Return a dict with the auth REST handlers.

        It should return a dict in this format:
        dict(
            authorized_handler='path_to_method_authorized_signup_handler',
            disconnect_handler='path_to_method_disconnect_rest_handler',
            signup_handler=dict(
                info='path_to_method_account_info',
                setup='path_to_method_account_setup',
                view='path_to_method_signup_form_handler',
            ),
            response_handler=(
                'path_to_method_response_handler'
            ),
            authorized_redirect_url='/',
            disconnect_redirect_url='/',
            signup_redirect_url='/',
            error_redirect_url='/'
        )
        """
        raise NotImplementedError

    @cached_property
    def remote_rest_app(self):
        """Crete a KEYCLOAK_REMOTE_REST_APP using the given configuration."""
        self._remote_rest_app = dict(self.base_app)
        self._remote_rest_app.update(self.get_rest_handlers())
        return self._remote_rest_app
