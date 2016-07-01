# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2014, 2015, 2016 CERN.
#
# Invenio is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# Invenio is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Invenio; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.

"""Models for storing access tokens and links between users and remote apps."""

from flask import current_app
from invenio_accounts.models import User
from invenio_db import db
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy_utils import JSONType
from sqlalchemy_utils.types.encrypted import EncryptedType


def _secret_key():
    """Return secret key from current application."""
    return current_app.config.get('SECRET_KEY')


class RemoteAccount(db.Model):
    """Storage for remote linked accounts."""

    __tablename__ = 'oauthclient_remoteaccount'

    __table_args__ = (
        db.UniqueConstraint('user_id', 'client_id'),
    )

    #
    # Fields
    #
    id = db.Column(
        db.Integer,
        primary_key=True,
        autoincrement=True
    )
    """Primary key."""

    user_id = db.Column(
        db.Integer,
        db.ForeignKey(User.id),
        nullable=False
    )
    """Local user linked with a remote app via the access token."""

    client_id = db.Column(db.String(255), nullable=False)
    """Client ID of remote application (defined in OAUTHCLIENT_REMOTE_APPS)."""

    extra_data = db.Column(MutableDict.as_mutable(JSONType), nullable=False)
    """Extra data associated with this linked account."""

    #
    # Relationships propoerties
    #
    user = db.relationship('User')
    """SQLAlchemy relationship to user."""

    tokens = db.relationship(
        'RemoteToken',
        backref='remote_account',
        cascade='all, delete-orphan'
    )
    """SQLAlchemy relationship to RemoteToken objects."""

    @classmethod
    def get(cls, user_id, client_id):
        """Get RemoteAccount object for user.

        :param user_id: User id
        :param client_id: Client id.
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
        """
        with db.session.begin_nested():
            account = cls(
                user_id=user_id,
                client_id=client_id,
                extra_data=extra_data or dict()
            )
            db.session.add(account)
        return account

    def delete(self):
        """Delete remote account together with all stored tokens."""
        with db.session.begin_nested():
            db.session.delete(self)

    def __repr__(self):
        """String representation for model."""
        return 'Remote Account <id={0.id}, user_id={0.user.id}>'.format(self)


class RemoteToken(db.Model):
    """Storage for the access tokens for linked accounts."""

    __tablename__ = 'oauthclient_remotetoken'

    #
    # Fields
    #
    id_remote_account = db.Column(
        db.Integer,
        db.ForeignKey(RemoteAccount.id),
        nullable=False,
        primary_key=True
    )
    """Foreign key to account."""

    token_type = db.Column(
        db.String(40), default='', nullable=False, primary_key=True
    )
    """Type of token."""

    access_token = db.Column(
        EncryptedType(type_in=db.Text, key=_secret_key), nullable=False
    )
    """Access token to remote application."""

    secret = db.Column(db.Text(), default='', nullable=False)
    """Used only by OAuth 1."""

    def __repr__(self):
        """String representation for model."""
        return ('Remote Token <token_type={0.token_type} '
                'access_token={0.access_token}'.format(self))

    def token(self):
        """Get token as expected by Flask-OAuthlib."""
        return (self.access_token, self.secret)

    def update_token(self, token, secret):
        """Update token with new values."""
        if self.access_token != token or self.secret != secret:
            with db.session.begin_nested():
                self.access_token = token
                self.secret = secret
                db.session.add(self)

    @classmethod
    def get(cls, user_id, client_id, token_type='', access_token=None):
        """Get RemoteToken for user."""
        args = [
            RemoteAccount.id == RemoteToken.id_remote_account,
            RemoteAccount.user_id == user_id,
            RemoteAccount.client_id == client_id,
            RemoteToken.token_type == token_type,
        ]

        if access_token:
            args.append(RemoteToken.access_token == access_token)

        return cls.query.options(
            db.joinedload('remote_account')
        ).filter(*args).first()

    @classmethod
    def get_by_token(cls, client_id, access_token, token_type=''):
        """Get RemoteAccount object for token."""
        return cls.query.options(db.joinedload('remote_account')).filter(
            RemoteAccount.id == RemoteToken.id_remote_account,
            RemoteAccount.client_id == client_id,
            RemoteToken.token_type == token_type,
            RemoteToken.access_token == access_token,
        ).first()

    @classmethod
    def create(cls, user_id, client_id, token, secret,
               token_type='', extra_data=None):
        """Create a new access token.

        Creates RemoteAccount as well if it does not exists.
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


class UserIdentity(db.Model):
    """Represent a UserIdentity record."""

    __tablename__ = 'oauthclient_useridentity'

    id = db.Column(db.String(255), primary_key=True, nullable=False)
    method = db.Column(db.String(255), primary_key=True, nullable=False)
    id_user = db.Column(db.Integer(),
                        db.ForeignKey(User.id), nullable=False)

    user = db.relationship(User, backref='external_identifiers')

    __table_args__ = (
        db.Index('useridentity_id_user_method', id_user, method, unique=True),
    )

__all__ = ('RemoteAccount', 'RemoteToken', 'UserIdentity')
