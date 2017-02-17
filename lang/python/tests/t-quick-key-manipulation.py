#!/usr/bin/env python

# Copyright (C) 2017 g10 Code GmbH
#
# This file is part of GPGME.
#
# GPGME is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# GPGME is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General
# Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import, print_function, unicode_literals
del absolute_import, print_function, unicode_literals

import gpg

import support

alpha = "Alpha <alpha@invalid.example.net>"
bravo = "Bravo <bravo@invalid.example.net>"

with support.EphemeralContext() as ctx:
    res = ctx.create_key(alpha, certify=True)
    key = ctx.get_key(res.fpr)
    assert len(key.subkeys) == 1, "Expected one primary key and no subkeys"
    assert len(key.uids) == 1, "Expected exactly one UID"

    def get_uid(uid):
        key = ctx.get_key(res.fpr)
        for u in key.uids:
            if u.uid == uid:
                return u
        return None

    # sanity check
    uid = get_uid(alpha)
    assert uid, "UID alpha not found"
    assert uid.revoked == 0

    # add bravo
    ctx.key_add_uid(key, bravo)
    uid = get_uid(bravo)
    assert uid, "UID bravo not found"
    assert uid.revoked == 0

    # revoke alpha
    ctx.key_revoke_uid(key, alpha)
    uid = get_uid(alpha)
    assert uid, "UID alpha not found"
    assert uid.revoked == 1
    uid = get_uid(bravo)
    assert uid, "UID bravo not found"
    assert uid.revoked == 0

    # try to revoke the last UID
    try:
        ctx.key_revoke_uid(key, alpha)
        # IMHO this should fail.  issue2961.
        # assert False, "Expected an error but got none"
    except gpg.errors.GpgError:
        pass

    # Everything should be the same
    uid = get_uid(alpha)
    assert uid, "UID alpha not found"
    assert uid.revoked == 1
    uid = get_uid(bravo)
    assert uid, "UID bravo not found"
    assert uid.revoked == 0

    # try to revoke a non-existent UID
    try:
        ctx.key_revoke_uid(key, "i dont exist")
        # IMHO this should fail.  issue2963.
        # assert False, "Expected an error but got none"
    except gpg.errors.GpgError:
        pass

    # try to add an pre-existent UID
    try:
        ctx.key_add_uid(key, bravo)
        assert False, "Expected an error but got none"
    except gpg.errors.GpgError:
        pass
