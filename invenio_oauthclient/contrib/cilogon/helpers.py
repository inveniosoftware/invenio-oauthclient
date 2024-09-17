"""Helper functions for the endpoint handlers."""

import re
import base64
import jwt
import six
import struct
from datetime import datetime, timezone

from flask import current_app

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.backends import default_backend
from invenio_oauthclient.errors import OAuthCilogonRejectedAccountError

from ...errors import OAuthError

AZ_09_DASHES_UNDERSCORES = r"^[A-Za-z0-9_-]+$"

def is_app_name_valid(app_name):
    """Validate app name."""
    return re.match(AZ_09_DASHES_UNDERSCORES, app_name) is not None

def _generate_config_prefix(remote):
    """Validate the app name so that it can be used in config vars."""
    app_name = remote.name
    if not is_app_name_valid(app_name):
        raise OAuthError(
            f"Invalid app name {app_name}. "
            "It should only contain letters, numbers, dashes "
            "and underscores",
            remote,
        )
    return f"OAUTHCLIENT_{app_name.upper()}"

def jwks2pem(jwks):
    def intarr2long(arr):
        return int(''.join(["%02x" % byte for byte in arr]), 16)

    def base64_to_long(data):
        if isinstance(data, six.text_type):
            data = data.encode("ascii")
        # urlsafe_b64decode will happily convert b64encoded data
        _d = base64.urlsafe_b64decode(bytes(data) + b'==')
        return intarr2long(struct.unpack('%sB' % len(_d), _d))

    pems = {}
    for jwk in jwks['keys']:
        alg = jwk['alg']
        exponent = base64_to_long(jwk['e'])
        modulus = base64_to_long(jwk['n'])
        numbers = RSAPublicNumbers(exponent, modulus)
        public_key = numbers.public_key(backend=default_backend())
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pems[alg] = pem
    return pems

def get_all_keys(remote, jwsurl):
    keys = remote.get(jwsurl).data
    try:
        return jwks2pem(keys)
    except Exception as e:
        return {}

def _get_user_info_from_token(remote, token, config_prefix):
    """Get the user information from the JWT token."""
    jwsurl = current_app.config.get(f"{config_prefix}_JWKS_URL")
    pubkeys = get_all_keys(remote=remote, jwsurl=jwsurl)
    # pubkey = _format_public_key(get_public_key(remote))
    alg = jwt.get_unverified_header(token)["alg"]
    try:
        # pubkey = _format_public_key(pubkeys[alg])
        #pubkey = _format_public_key(pubkeys[alg])
        pubkey = pubkeys[alg]
    except Exception as e:
        return None


    should_verify_aud = current_app.config.get(f"{config_prefix}_VERIFY_AUD", False)
    expected_aud = current_app.config.get(f"{config_prefix}_AUD", None)

    should_verify_expiration = current_app.config.get(
        f"{config_prefix}_VERIFY_EXP", False
    )

    options = {
        # check signature expiration
        "verify_exp": should_verify_expiration,
        # check the target audience
        "verify_aud": should_verify_aud and (expected_aud is not None),
        'verify_signature':True
    }

    decodedToken = jwt.decode(
        token, key=pubkey, algorithms=[alg], audience=expected_aud, options=options, verify=False,
    )
    return decodedToken

def _get_user_info_from_endpoint(remote, config_prefix):
    """Get the user info from the oauth server provider."""
    url = current_app.config[f"{config_prefix}_USER_INFO_URL"]
    return remote.get(url).data


def get_user_info(remote, resp_token, from_token_only=False):
    """Get the user information from Comanage.

    :param remote: The OAuthClient remote app
    :param resp_token: The response from the 'token' endpoint; expected to be a dict
        and to contain a JWT 'id_token'
    :param from_token_only: return info only from the token, without calling the
        user info endpoint.
    :returns: A tuple containing the user information extracted from the token, and
        if configured, from the UserInfo endpoint
    """
    config_prefix = _generate_config_prefix(remote)
    from_token, from_endpoint = {}, None
    try:
        from_token = _get_user_info_from_token(
            remote, resp_token["id_token"], config_prefix
        )
    except Exception as e:
        current_app.logger.exception(e)


    call_endpoint = current_app.config[f"{config_prefix}_USER_INFO_URL"]
    if not from_token_only and call_endpoint:
        from_endpoint = _get_user_info_from_endpoint(remote, config_prefix)

    return from_token, from_endpoint

def filter_groups(remote, resp, groups):
    """ Filter groups from local <config_prefix>_Allowed_ROLES.
    :param remote: The remote application.
    :param resp: The response of the `authorized` endpoint.
    :param groups: List of groups to filter from <config_prefix>_ALLOWED_ROLES
    :retruns: A List of matching groups.
    """
    config_prefix = _generate_config_prefix(remote)
    allow_any_groups = current_app.config.get(f"{config_prefix}_ALLOW_ANY_ROLES", False)
    if allow_any_groups:
        return []
    valid_roles = current_app.config[f"{config_prefix}_ALLOWED_ROLES"]
    matching_groups = [group for group in groups if group in valid_roles]
    if not matching_groups:
        # Return an error if no matching groups are found
        raise OAuthCilogonRejectedAccountError(
            "User roles/groups {0} are not one of allowed {1} roles/groups.".format(str(groups), str(valid_roles)),
            remote,
            {
                "status_code": 401,
                "error": {
                    "type": "OAuthCilogonRejectedAccountError",
                    "message": "User roles/groups {0} are not one of allowed {1} roles/groups.".format(str(groups), str(valid_roles)),
                    "details": {
                        "roles_provided": groups,
                        "valid_roles": valid_roles
                    }
                }
            }
            )
    return matching_groups

def get_groups(remote, resp, account, group_names):
    """ Get groups from filter_groups and add as account extra data.
    :param remote: The remote application.
    :param resp: The response of the `authorized` endpoint.
    :param account: The remote application.
    :param group_names: List of group names to filter from <config_prefix>_ALLOWED_ROLES.
    :returns: A list of matching groups.
    """
    roles = filter_groups(remote, resp, group_names)
    updated = datetime.now(timezone.utc)
    account.extra_data.update(roles=roles, updated=updated.isoformat())
    return roles
