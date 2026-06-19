# SPDX-FileCopyrightText: 2026 CERN.
# SPDX-License-Identifier: MIT

"""Tests for the ``icon_image`` provider logo configuration."""

import pytest
from flask import render_template_string

from invenio_oauthclient.contrib.eosc_aai import REMOTE_APP as EOSC_REMOTE_APP
from invenio_oauthclient.contrib.openaire_aai import REMOTE_APP as OPENAIRE_REMOTE_APP
from invenio_oauthclient.contrib.openaire_aai import (
    REMOTE_SANDBOX_APP as OPENAIRE_SANDBOX_APP,
)
from invenio_oauthclient.contrib.orcid import REMOTE_APP as ORCID_REMOTE_APP
from invenio_oauthclient.contrib.orcid import ORCIDOAuthSettingsHelper
from invenio_oauthclient.contrib.settings import OAuthSettingsHelper


def test_base_helper_defaults_icon_image_to_none():
    """Apps that don't set a logo keep the previous (font-glyph) behavior."""
    helper = OAuthSettingsHelper("Title", "Desc", "https://example.org", "KEY")
    assert helper.base_app["icon_image"] is None


def test_base_helper_threads_icon_image():
    """A configured logo is exposed at the top level of the app dict."""
    helper = OAuthSettingsHelper(
        "Title",
        "Desc",
        "https://example.org",
        "KEY",
        icon_image="images/custom.svg",
    )
    assert helper.base_app["icon_image"] == "images/custom.svg"


@pytest.mark.parametrize(
    "remote_app, expected",
    [
        (ORCID_REMOTE_APP, "images/oauthclient/orcid.svg"),
        (OPENAIRE_REMOTE_APP, "images/oauthclient/openaire.svg"),
        (OPENAIRE_SANDBOX_APP, "images/oauthclient/openaire.svg"),
        (EOSC_REMOTE_APP, "images/oauthclient/eosc.svg"),
    ],
)
def test_contrib_defaults_to_bundled_logo(remote_app, expected):
    """ORCID, OpenAIRE and EOSC point at their bundled, namespaced logo."""
    assert remote_app["icon_image"] == expected


def test_icon_image_is_overridable():
    """Deployers can swap in their own logo."""
    helper = ORCIDOAuthSettingsHelper(icon_image="images/my-orcid.svg")
    assert helper.remote_app["icon_image"] == "images/my-orcid.svg"


@pytest.mark.parametrize(
    "macro_template",
    [
        "semantic-ui/invenio_oauthclient/_macros.html",
        "invenio_oauthclient/_macros.html",
    ],
)
def test_oauth_button_renders_logo_or_glyph(app, macro_template):
    """A logo renders as an <img> via the static endpoint; otherwise a glyph."""
    app.config["OAUTHCLIENT_REMOTE_APPS"] = {
        "orcid": {
            "title": "ORCID",
            "icon": "",
            "icon_image": "images/oauthclient/orcid.svg",
        },
        "github": {"title": "GitHub", "icon": "fa fa-github"},  # no icon_image
    }
    tpl = (
        "{% from '" + macro_template + "' import oauth_button %}"
        "{{ oauth_button('orcid') }}|{{ oauth_button('github') }}"
    )
    with app.test_request_context("/"):
        html = render_template_string(tpl)

    assert 'src="/static/images/oauthclient/orcid.svg"' in html
    # GitHub has no logo configured, so it keeps its font glyph (no <img>).
    assert "github" in html
    assert html.count("<img") == 1
