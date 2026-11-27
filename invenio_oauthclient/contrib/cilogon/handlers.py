from flask import current_app, g, redirect, session, url_for
from flask_login import current_user
from flask_principal import (
    AnonymousIdentity,
    RoleNeed,
    UserNeed,
    identity_changed,
    identity_loaded,
)
from invenio_db import db
from invenio_i18n import gettext as _
from invenio_oauthclient import current_oauthclient
from invenio_oauthclient.errors import OAuthCilogonRejectedAccountError
from invenio_oauthclient.handlers.rest import response_handler
from invenio_oauthclient.handlers.utils import require_more_than_one_external_account
from invenio_oauthclient.models import RemoteAccount
from invenio_oauthclient.oauth import oauth_link_external_id, oauth_unlink_external_id

from .helpers import filter_groups, get_groups, get_user_info

OAUTHCLIENT_CILOGON_SESSION_KEY = "identity.cilogon_provides"
OAUTHCLIENT_CILOGON_GROUP_OIDC_CLAIM = "isMemberOf, member_of"


def extend_identity(identity, roles):
    print("BEFORE PROVIDES")
    if not roles:
        provides = {UserNeed(current_user.email)}
    else:
        provides = set(
            [UserNeed(current_user.email)] + [RoleNeed(name) for name in roles]
        )
    identity.provides |= provides
    key = current_app.config.get(
        "OAUTHCLIENT_CILOGON_SESSION_KEY",
        OAUTHCLIENT_CILOGON_SESSION_KEY,
    )
    session[key] = provides


def disconnect_identity(identity):
    key = current_app.config.get(
        "OAUTHCLIENT_CILOGON_SESSION_KEY",
        OAUTHCLIENT_CILOGON_SESSION_KEY,
    )
    provides = session.pop(key, set())
    identity.provides -= provides


def extract_group_claim_names():
    raw = current_app.config.get(
        "OAUTHCLIENT_CILOGON_GROUP_OIDC_CLAIM",
        OAUTHCLIENT_CILOGON_GROUP_OIDC_CLAIM,
    )
    return [c.strip() for c in raw.split(",") if c.strip()]


def extract_group_names(
    token_user_info, user_info, group_claim_names, deduplicate=True
):
    group_names = []

    for claim in group_claim_names:
        values = token_user_info.get(claim) or user_info.get(claim)

        if not values:
            continue

        if isinstance(values, list):
            group_names.extend(values)

        elif isinstance(values, str):
            group_names.extend([v.strip() for v in values.split(";") if v.strip()])

        else:
            group_names.append(str(values))

    if deduplicate:
        return list(set(group_names))
    print(f"[CILOGON] final group_names AFTER dedupe = {group_names}")
    return group_names


def info_serializer_handler(remote, resp, token_user_info, user_info=None, **kwargs):
    """Serialize the account info response object.

    :param remote: The remote application.
    :param resp: The response of the `authorized` endpoint.
    :param token_user_info: The content of the authorization token response.
    :param user_info: The response of the `user info` endpoint.
    :returns: A dictionary with serialized user information.
    """
    # fill out the information required by
    # 'invenio-accounts' and 'invenio-userprofiles'.

    user_info = user_info or {}  # prevent errors when accessing None.get(...)

    email = token_user_info.get("email") or user_info.get("email")
    full_name = token_user_info.get("name") or user_info.get("name")
    username = token_user_info.get("preferred_username") or user_info.get(
        "preferred_username"
    )
    cilogonid = token_user_info.get("sub") or user_info.get("sub")
    if not username and email:
        username = email.split("@")[0]
    affiliation = (
        token_user_info.get("idp_name")
        or user_info.get("idp_name")
        or token_user_info.get("ou")
        or user_info.get("ou")
    )

    # check for matching group

    group_claim_names = extract_group_claim_names()

    group_names = extract_group_names(
        token_user_info,
        user_info,
        group_claim_names,
    )
    filter_groups(remote, resp, group_names)
    return {
        "user": {
            "active": True,
            "email": email,
            "profile": {
                "full_name": full_name,
                "username": username,
            },
        },
        "external_id": cilogonid,
        "external_method": remote.name,
    }


def info_handler(remote, resp):
    """Retrieve remote account information for finding matching local users.

    :param remote: The remote application.
    :param resp: The response of the `authorized` endpoint.
    :returns: A dictionary with the user information.
    """
    token_user_info, user_info = get_user_info(remote, resp)
    handlers = current_oauthclient.signup_handlers[remote.name]
    # `remote` param automatically injected via `make_handler` helper
    return handlers["info_serializer"](resp, token_user_info, user_info)


def group_serializer_handler(remote, resp, token_user_info, user_info=None, **kwargs):
    """Retrieve remote account information for group for finding matching local groups.

    :param remote: The remote application.
    :param resp: The response of the `authorized` endpoint.
    :returns: A dictionary with the user information.
    """
    user_info = user_info or {}  # prevent errors when accessing None.get(...)
    group_claim_names = extract_group_claim_names()

    group_names = extract_group_names(
        token_user_info,
        user_info,
        group_claim_names,
    )
    groups_dict_list = []
    # check for matching group
    try:
        matching_groups = filter_groups(remote, resp, group_names)
        for group in matching_groups:
            group_dict = {"id": group, "name": group, "description": ""}
            groups_dict_list.append(group_dict)
        return groups_dict_list

    except OAuthCilogonRejectedAccountError as e:
        current_app.logger.warning(e.message, exc_info=False)
        return groups_dict_list


def group_rest_serializer_handler(
    remote, resp, token_user_info, user_info=None, **kwargs
):
    """Retrieve remote account information for group for finding matching local groups.

    :param remote: The remote application.
    :param resp: The response of the `authorized` endpoint.
    :returns: A dictionary with the user information.
    """
    user_info = user_info or {}  # prevent errors when accessing None.get(...)
    group_claim_names = extract_group_claim_names()
    group_names = extract_group_names(
        token_user_info,
        user_info,
        group_claim_names,
    )
    groups_dict_list = []
    # check for matching group
    try:
        matching_groups = filter_groups(remote, resp, group_names)
        for group in matching_groups:
            group_dict = {"id": group, "name": group, "description": ""}
            groups_dict_list.append(group_dict)
        return groups_dict_list

    except OAuthCilogonRejectedAccountError as e:
        current_app.logger.warning(e.message, exc_info=False)
        return groups_dict_list


def group_handler(remote, resp):
    """Retrieve remote account information for finding matching local users.

    :param remote: The remote application.
    :param resp: The response of the `authorized` endpoint.
    :returns: A dictionary with the user information.
    """
    token_user_info, user_info = get_user_info(remote, resp)
    handlers = current_oauthclient.signup_handlers[remote.name]
    # `remote` param automatically injected via `make_handler` helper
    return handlers["groups_serializer"](resp, token_user_info, user_info)


def setup_handler(remote, token, resp):
    """Perform additional setup after the user has been logged in."""
    token_user_info, _ = get_user_info(remote, resp, from_token_only=True)

    with db.session.begin_nested():
        # fetch the user's cilogon ID (sub) and set it in extra_data
        cilogonid = token_user_info["sub"]
        token.remote_account.extra_data = {
            "cilogonid": cilogonid,
        }

        user = token.remote_account.user
        external_id = {"id": cilogonid, "method": remote.name}

        group_claim_names = extract_group_claim_names()

        group_names = extract_group_names(
            token_user_info,
            {},
            group_claim_names,
        )
        roles = get_groups(remote, resp, token.remote_account, group_names)
        assert not isinstance(g.identity, AnonymousIdentity)
        extend_identity(g.identity, roles)
        g.oauth_logged_in_with_remote = remote
        # link account with external cilogon ID
        oauth_link_external_id(user, external_id)


@require_more_than_one_external_account
def _disconnect(remote, *args, **kwargs):
    """Common logic for handling disconnection of remote accounts."""
    if not current_user.is_authenticated:
        return current_app.login_manager.unauthorized()

    account = RemoteAccount.get(
        user_id=current_user.get_id(), client_id=remote.consumer_key
    )

    cilogonid = account.extra_data.get("cilogonid")

    if cilogonid:
        external_id = {"id": cilogonid, "method": remote.name}

        oauth_unlink_external_id(external_id)

    if account:
        with db.session.begin_nested():
            account.delete()
    disconnect_identity(g.identity)


def disconnect_handler(remote, *args, **kwargs):
    """Handle unlinking of the remote account."""
    _disconnect(remote, *args, **kwargs)
    return redirect(url_for("invenio_oauthclient_settings.index"))


def disconnect_rest_handler(remote, *args, **kwargs):
    """Handle unlinking of the remote account."""
    _disconnect(remote, *args, **kwargs)
    rconfig = current_app.config["OAUTHCLIENT_REST_REMOTE_APPS"][remote.name]
    redirect_url = rconfig["disconnect_redirect_url"]
    return response_handler(remote, redirect_url)


@identity_changed.connect
def on_identity_changed(sender, identity):
    if isinstance(identity, AnonymousIdentity):
        disconnect_identity(identity)
        return

    if not current_user.is_authenticated:
        return

    remote = g.get("oauth_logged_in_with_remote", None)
    if not remote:
        return

    # Use the remote object's consumer_key directly — no config lookup needed
    remote_account = RemoteAccount.get(
        user_id=current_user.get_id(),
        client_id=remote.consumer_key,  # ← comes from the remote object itself
    )

    roles = []
    if remote_account:
        # roles were already written by get_groups() inside setup_handler
        roles = remote_account.extra_data.get("roles", [])

    extend_identity(identity, roles)


@identity_loaded.connect
def on_identity_loaded(sender, identity):
    key = current_app.config.get(
        "OAUTHCLIENT_CILOGON_SESSION_KEY", OAUTHCLIENT_CILOGON_SESSION_KEY
    )
    identity.provides.update(session.get(key, []))
