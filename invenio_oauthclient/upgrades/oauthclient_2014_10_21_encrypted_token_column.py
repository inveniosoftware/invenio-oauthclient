# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2014, 2015 CERN.
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


from invenio_ext.sqlalchemy import db

from invenio_upgrader.api import op

from ..models import RemoteToken, secret_key

depends_on = [u'oauthclient_2014_08_25_extra_data_nullable']


def info():
    return "Encrypt access tokens in remoteTOKEN table."


def do_upgrade():
    """Implement your upgrades here."""
    from sqlalchemy_utils.types.encrypted import AesEngine
    engine = AesEngine()
    engine._update_key(secret_key())
    with db.session.begin_nested():
        for row in db.session.execute(
                "SELECT id_remote_account, token_type, access_token "
                "FROM remoteTOKEN"):
            db.session.execute(
                "UPDATE remoteTOKEN SET access_token=:token "
                "WHERE id_remote_account=:account AND "
                "token_type=:type", {
                    'token': engine.encrypt(row[2]),
                    'account': row[0],
                    'type': row[1],
                })
    db.session.commit()


def estimate():
    """Estimate running time of upgrade in seconds (optional)."""
    if op.has_table('remoteTOKEN'):
        return RemoteToken.query.count()
    return 1
