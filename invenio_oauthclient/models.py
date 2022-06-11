# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Models for storing access tokens and links between users and remote apps."""

from flask import current_app

# UserIdentity imported for backward compatibility. UserIdentity was originally
# added to OAuthClient but has now been moved to Invenio-Accounts. Importing it
# here, means previous imports won't break.
from invenio_accounts.models import User, UserIdentity
from invenio_db import db
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.orm import backref
from sqlalchemy_utils import EncryptedType, JSONType, Timestamp


def _secret_key():
    """Return secret key from current application."""
    return current_app.config.get("SECRET_KEY")


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

    extra_data = db.Column(MutableDict.as_mutable(JSONType), nullable=False)
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
        EncryptedType(type_in=db.Text, key=_secret_key), nullable=False
    )
    """Access token to remote application."""

    secret = db.Column(db.Text(), default="", nullable=False)
    """Used only by OAuth 1."""

    #
    # Relationships properties
    #
    remote_account = db.relationship(
        RemoteAccount, backref=backref("remote_tokens", cascade="all, delete-orphan")
    )
    """SQLAlchemy relationship to RemoteAccount objects."""

    def __repr__(self):
        """String representation for model."""
        return (
            "Remote Token <token_type={0.token_type} "
            "access_token=****{1}>".format(self, self.access_token[-4:])
        )

    def token(self):
        """Get token as expected by Flask-OAuthlib."""
        return (self.access_token, self.secret)

    def update_token(self, token, secret):
        """Update token with new values.

        :param token: The token value.
        :param secret: The secret key.
        """
        if self.access_token != token or self.secret != secret:
            with db.session.begin_nested():
                self.access_token = token
                self.secret = secret
                db.session.add(self)

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

        return cls.query.options(db.joinedload("remote_account")).filter(*args).first()

    @classmethod
    def get_by_token(cls, client_id, access_token, token_type=""):
        """Get RemoteAccount object for token.

        :param client_id: The client id.
        :param access_token: The access token.
        :param token_type: The token type. (Default: ``''``)
        :returns: A :class:`invenio_oauthclient.models.RemoteToken` instance.
        """
        return (
            cls.query.options(db.joinedload("remote_account"))
            .filter(
                RemoteAccount.id == RemoteToken.id_remote_account,
                RemoteAccount.client_id == client_id,
                RemoteToken.token_type == token_type,
                RemoteToken.access_token == access_token,
            )
            .first()
        )

    @classmethod
    def create(cls, user_id, client_id, token, secret, token_type="", extra_data=None):
        """Create a new access token.

        .. note:: Creates RemoteAccount as well if it does not exists.

        :param user_id: The user id.
        :param client_id: The client id.
        :param token: The token.
        :param secret: The secret key.
        :param token_type: The token type. (Default: ``''``)
        :param extra_data: Extra data to set in the remote account if the
            remote account doesn't exists. (Default: ``None``)
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
            )
            db.session.add(token)
        return token


__all__ = ("RemoteAccount", "RemoteToken", "UserIdentity")
