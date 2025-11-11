# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2025 CERN.
# Copyright (C) 2024 Graz University of Technology.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Models for storing access tokens and links between users and remote apps."""

from datetime import datetime, timedelta, timezone

from flask import current_app

# UserIdentity imported for backward compatibility. UserIdentity was originally
# added to OAuthClient but has now been moved to Invenio-Accounts. Importing it
# here, means previous imports won't break.
from invenio_accounts.models import User, UserIdentity
from invenio_db import db
from sqlalchemy.dialects import mysql, postgresql
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.orm import backref
from sqlalchemy_utils import JSONType, StringEncryptedType, Timestamp


def _secret_key():
    """Return secret key from current application."""
    return current_app.config["SECRET_KEY"]


class RemoteAccount(db.Model, Timestamp):
    """Storage for remote linked accounts."""

    __tablename__ = "oauthclient_remoteaccount"

    __table_args__ = (db.UniqueConstraint("user_id", "client_id"),)

    #
    # Fields
    #
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    """Primary key."""

    user_id = db.Column(db.Integer, db.ForeignKey(User.id), nullable=False)
    """Local user linked with a remote app via the access token."""

    client_id = db.Column(db.String(255), nullable=False)
    """Client ID of remote application (defined in OAUTHCLIENT_REMOTE_APPS)."""

    extra_data = db.Column(
        MutableDict.as_mutable(
            db.JSON()
            .with_variant(postgresql.JSONB(), "postgresql")
            .with_variant(JSONType(), "sqlite")
            .with_variant(JSONType(), "mysql")
        ),
        nullable=False,
    )
    """Extra data associated with this linked account."""

    #
    # Relationships properties
    #
    user = db.relationship(User, backref="remote_accounts")
    """SQLAlchemy relationship to user."""

    @classmethod
    def get(cls, user_id, client_id):
        """Get RemoteAccount object for user.

        :param user_id: User id
        :param client_id: Client id.
        :returns: A :class:`invenio_oauthclient.models.RemoteAccount` instance.
        """
        return cls.query.filter_by(
            user_id=user_id,
            client_id=client_id,
        ).first()

    @classmethod
    def create(cls, user_id, client_id, extra_data):
        """Create new remote account for user.

        :param user_id: User id.
        :param client_id: Client id.
        :param extra_data: JSON-serializable dictionary of any extra data that
            needs to be save together with this link.
        :returns: A :class:`invenio_oauthclient.models.RemoteAccount` instance.
        """
        with db.session.begin_nested():
            account = cls(
                user_id=user_id, client_id=client_id, extra_data=extra_data or dict()
            )
            db.session.add(account)
        return account

    def delete(self):
        """Delete remote account together with all stored tokens."""
        with db.session.begin_nested():
            db.session.delete(self)

    def __repr__(self):
        """String representation for model."""
        return "Remote Account <id={0.id}, user_id={0.user.id}>".format(self)


class RemoteToken(db.Model, Timestamp):
    """Storage for the access tokens for linked accounts."""

    __tablename__ = "oauthclient_remotetoken"

    #
    # Fields
    #
    id_remote_account = db.Column(
        db.Integer,
        db.ForeignKey(
            RemoteAccount.id, name="fk_oauthclient_remote_token_remote_account"
        ),
        nullable=False,
        primary_key=True,
    )
    """Foreign key to account."""

    token_type = db.Column(db.String(40), default="", nullable=False, primary_key=True)
    """Type of token."""

    access_token = db.Column(
        StringEncryptedType(type_in=db.Text, key=_secret_key), nullable=False
    )
    """Access token to remote application."""

    refresh_token = db.Column(
        StringEncryptedType(type_in=db.Text, key=_secret_key), nullable=True
    )
    """Refresh token to remote application."""

    expires = db.Column(
        db.DateTime().with_variant(mysql.DATETIME(fsp=6), "mysql"), nullable=True
    )
    """Access token expiration date."""

    secret = db.Column(db.Text(), default="", nullable=False)
    """Used only by OAuth 1."""

    #
    # Relationships properties
    #
    remote_account = db.relationship(
        RemoteAccount, backref=backref("remote_tokens", cascade="all, delete-orphan")
    )
    """SQLAlchemy relationship to RemoteAccount objects."""

    @property
    def is_expired(self):
        """Check if access token has expired."""
        if not self.expires:
            return False

        leeway = current_app.config.get("OAUTHCLIENT_TOKEN_EXPIRES_LEEWAY", 10)
        expiration_with_leeway = (self.expires - timedelta(seconds=leeway)).replace(
            # see https://docs.sqlalchemy.org/en/13/core/type_basics.html#sqlalchemy.types.DateTime
            # We store datetimes in the DB as UTC but without timezone metadata. So to make comparison
            # possible, we need to mark this as UTC.
            tzinfo=timezone.utc
        )
        return expiration_with_leeway < datetime.now(tz=timezone.utc)

    def __repr__(self):
        """String representation for model."""
        return (
            "Remote Token <token_type={0.token_type} "
            "access_token=****{1}>".format(self, self.access_token[-4:])
        )

    def token(self):
        """Get token as expected by Flask-OAuthlib."""
        return (self.access_token, self.secret)

    def update_token(self, token, secret, refresh_token=None, expires=None):
        """Update token with new values.

        :param token: The token value.
        :param secret: The secret key.
        :param refresh_token: The refresh token
        :param expires: Time when the access token expires
        """
        if (
            self.access_token != token
            or self.secret != secret
            or self.refresh_token != refresh_token
            or self.expires != expires
        ):
            with db.session.begin_nested():
                self.access_token = token
                self.secret = secret
                self.refresh_token = refresh_token
                self.expires = expires
                db.session.add(self)

    def refresh_access_token(self):
        """Refresh the access token.

        Warning: due to the irreversibility of the OAuth refresh call, this method calls `db.session.commit()`. Make sure
        to call this method _before_ any business logic that is intended to be rollbackable, as this call may inadvertently
        commit unrelated transactions.
        """
        if not self.refresh_token:
            raise ValueError("No refresh token available")
        from .handlers.refresh import refresh_access_token

        access_token, refresh_token, expires = refresh_access_token(self)
        # Refresh tokens are a feature only in OAuth 2.0, so we never store a secret.
        self.update_token(access_token, "", refresh_token, expires)
        # Refreshing the token is an operation that cannot be rolled back. The old access token is usually not invalidated
        # (this is not required by the RFC but is allowed), but e.g. if the server issues a new refresh token that is something
        # we cannot undo. The old token may be revoked. Therefore, we must commit the update straight away: rolling back the
        # token update would create an inconsistency and we risk permanently losing access to the remote account.
        # See RFC 6749 Section 6 for more details.
        db.session.commit()

    @classmethod
    def get(cls, user_id, client_id, token_type="", access_token=None):
        """Get RemoteToken for user.

        :param user_id: The user id.
        :param client_id: The client id.
        :param token_type: The token type. (Default: ``''``)
        :param access_token: If set, will filter also by access token.
            (Default: ``None``)
        :returns: A :class:`invenio_oauthclient.models.RemoteToken` instance.
        """
        args = [
            RemoteAccount.id == RemoteToken.id_remote_account,
            RemoteAccount.user_id == user_id,
            RemoteAccount.client_id == client_id,
            RemoteToken.token_type == token_type,
        ]

        if access_token:
            args.append(RemoteToken.access_token == access_token)

        return (
            cls.query.options(db.joinedload(RemoteToken.remote_account))
            .filter(*args)
            .first()
        )

    @classmethod
    def get_by_token(cls, client_id, access_token, token_type=""):
        """Get RemoteAccount object for token.

        :param client_id: The client id.
        :param access_token: The access token.
        :param token_type: The token type. (Default: ``''``)
        :returns: A :class:`invenio_oauthclient.models.RemoteToken` instance.
        """
        return (
            cls.query.options(db.joinedload(RemoteToken.remote_account))
            .filter(
                RemoteAccount.id == RemoteToken.id_remote_account,
                RemoteAccount.client_id == client_id,
                RemoteToken.token_type == token_type,
                RemoteToken.access_token == access_token,
            )
            .first()
        )

    @classmethod
    def create(
        cls,
        user_id,
        client_id,
        token,
        secret,
        token_type="",
        extra_data=None,
        refresh_token=None,
        expires=None,
    ):
        """Create a new access token.

        .. note:: Creates RemoteAccount as well if it does not exists.

        :param user_id: The user id.
        :param client_id: The client id.
        :param token: The token.
        :param secret: The secret key.
        :param token_type: The token type. (Default: ``''``)
        :param extra_data: Extra data to set in the remote account if the
            remote account doesn't exists. (Default: ``None``)
        :param refresh_token: The refresh token.
        :param expires: Expiration of the token
        :returns: A :class:`invenio_oauthclient.models.RemoteToken` instance.

        """
        account = RemoteAccount.get(user_id, client_id)

        with db.session.begin_nested():
            if account is None:
                account = RemoteAccount(
                    user_id=user_id,
                    client_id=client_id,
                    extra_data=extra_data or dict(),
                )
                db.session.add(account)

            token = cls(
                token_type=token_type,
                remote_account=account,
                access_token=token,
                secret=secret,
                refresh_token=refresh_token,
                expires=expires,
            )
            db.session.add(token)
        return token


__all__ = ("RemoteAccount", "RemoteToken", "UserIdentity")
