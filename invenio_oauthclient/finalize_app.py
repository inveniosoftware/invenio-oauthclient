# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2023 Graz University of Technology.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Finalize app."""


def finalize_app(app):
    """Finalize app."""

    override_template_configuration(app)


def override_template_configuration(app):
    """Override template configuration."""
    template_key = app.config.get(
        "OAUTHCLIENT_TEMPLATE_KEY",
        "SECURITY_LOGIN_USER_TEMPLATE",  # default template key
    )
    if template_key is not None:
        template = app.config[template_key]  # keep the old value
        app.config["OAUTHCLIENT_LOGIN_USER_TEMPLATE_PARENT"] = template
        app.config[template_key] = app.config.get(
            "OAUTHCLIENT_LOGIN_USER_TEMPLATE",
            "invenio_oauthclient/login_user.html",
        )
