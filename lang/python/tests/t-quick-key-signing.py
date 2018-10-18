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

import gpg
import itertools
import time

import support
support.assert_gpg_version((2, 1, 1))

del absolute_import, print_function, unicode_literals

with support.EphemeralContext() as ctx:
    uid_counter = 0

    def make_uid():
        global uid_counter
        uid_counter += 1
        return "user{0}@invalid.example.org".format(uid_counter)

    def make_key():
        uids = [make_uid() for i in range(3)]
        res = ctx.create_key(uids[0], certify=True)
        key = ctx.get_key(res.fpr)
        for u in uids[1:]:
            ctx.key_add_uid(key, u)
        return key, uids

    def check_sigs(key, expected_sigs):
        keys = list(
            ctx.keylist(
                key.fpr,
                mode=(gpg.constants.keylist.mode.LOCAL |
                      gpg.constants.keylist.mode.SIGS)))
        assert len(keys) == 1
        key_uids = {
            uid.uid: [s for s in uid.signatures]
            for uid in keys[0].uids
        }
        expected = list(expected_sigs)

        while key_uids and expected:
            uid, signing_key, func = expected[0]
            match = False
            for i, s in enumerate(key_uids[uid]):
                if signing_key.fpr.endswith(s.keyid):
                    if func:
                        func(s)
                    match = True
                    break
            if match:
                expected.pop(0)
                key_uids[uid].pop(i)
                if not key_uids[uid]:
                    del key_uids[uid]

        assert not key_uids, "Superfluous signatures: {0}".format(key_uids)
        assert not expected, "Missing signatures: {0}".format(expected)

    # Simplest case.  Sign without any options.
    key_a, uids_a = make_key()
    key_b, uids_b = make_key()
    ctx.signers = [key_a]

    def exportable_non_expiring(s):
        assert s.exportable
        assert s.expires == 0

    check_sigs(key_b,
               itertools.product(uids_b, [key_b], [exportable_non_expiring]))
    ctx.key_sign(key_b)
    check_sigs(
        key_b,
        itertools.product(uids_b, [key_b, key_a], [exportable_non_expiring]))

    # Create a non-exportable signature, and explicitly name all uids.
    key_c, uids_c = make_key()
    ctx.signers = [key_a, key_b]

    def non_exportable_non_expiring(s):
        assert s.exportable == 0
        assert s.expires == 0

    ctx.key_sign(key_c, local=True, uids=uids_c)
    check_sigs(
        key_c,
        list(itertools.product(uids_c, [key_c], [exportable_non_expiring])) +
        list(
            itertools.product(uids_c, [key_b, key_a],
                              [non_exportable_non_expiring])))

    # Create a non-exportable, expiring signature for a single uid.
    key_d, uids_d = make_key()
    ctx.signers = [key_c]
    expires_in = 600
    slack = 10

    def non_exportable_expiring(s):
        assert s.exportable == 0
        assert abs(time.time() + expires_in - s.expires) < slack

    ctx.key_sign(key_d, local=True, expires_in=expires_in, uids=uids_d[0])
    check_sigs(
        key_d,
        list(itertools.product(uids_d, [key_d], [exportable_non_expiring])) +
        list(
            itertools.product(uids_d[:1], [key_c], [non_exportable_expiring])))

    # Now sign the second in the same fashion, but use a singleton list.
    ctx.key_sign(key_d, local=True, expires_in=expires_in, uids=uids_d[1:2])
    check_sigs(
        key_d,
        list(itertools.product(uids_d, [key_d], [exportable_non_expiring])) +
        list(
            itertools.product(uids_d[:2], [key_c], [non_exportable_expiring])))
