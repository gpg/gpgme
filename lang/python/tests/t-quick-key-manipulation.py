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
# License along with this program; if not, see <https://www.gnu.org/licenses/>.

from __future__ import absolute_import, print_function, unicode_literals

import os
import gpg
import sys

import support
support.assert_gpg_version((2, 1, 14))

del absolute_import, print_function, unicode_literals

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
        ctx.key_revoke_uid(key, "i don't exist")
        # IMHO this should fail.  issue2963.
        # assert False, "Expected an error but got none"
    except gpg.errors.GpgError:
        pass

    # try to add a pre-existent UID
    try:
        ctx.key_add_uid(key, bravo)
        assert False, "Expected an error but got none"
    except gpg.errors.GpgError:
        pass

    # Check setting the TOFU policy.
    with open(os.path.join(ctx.home_dir, "gpg.conf"), "a") as handle:
        handle.write("trust-model tofu+pgp\n")

    if not support.have_tofu_support(ctx, bravo):
        print("GnuPG does not support TOFU, skipping TOFU tests.")
        sys.exit()

    for name, policy in [(name, getattr(gpg.constants.tofu.policy, name))
                         for name in filter(lambda x: not x.startswith('__'),
                                            dir(gpg.constants.tofu.policy))]:
        if policy == gpg.constants.tofu.policy.NONE:
            # We must not set the policy to NONE.
            continue

        ctx.key_tofu_policy(key, policy)

        keys = list(
            ctx.keylist(
                key.uids[0].uid,
                mode=(gpg.constants.keylist.mode.LOCAL |
                      gpg.constants.keylist.mode.WITH_TOFU)))
        assert len(keys) == 1

        if policy == gpg.constants.tofu.policy.AUTO:
            # We cannot check that it is set to AUTO.
            continue

        for uid in keys[0].uids:
            if uid.uid == alpha:
                # TOFU information of revoked UIDs is not updated.
                # XXX: Is that expected?
                continue
            assert uid.tofu[0].policy == policy, \
                "Expected policy {0} ({1}), got {2}".format(policy, name,
                                                            uid.tofu[0].policy)
