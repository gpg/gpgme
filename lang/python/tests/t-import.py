#!/usr/bin/env python

# Copyright (C) 2016 g10 Code GmbH
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

from pyme import core, constants
import support

def check_result(result, fpr, secret):
    assert result.considered == 1 or (secret and result.considered == 3)
    assert result.no_user_id == 0
    assert not ((secret and result.imported != 0)
                or (not secret and (result.imported != 0
                                    and result.imported != 1)))
    assert result.imported_rsa == 0
    assert not ((secret and (result.unchanged != 0 and result.unchanged != 1))
                or (not secret and ((result.imported == 0
                                     and result.unchanged != 1)
                                 or (result.imported == 1
                                     and result.unchanged != 0))))
    assert result.new_user_ids == 0
    assert result.new_sub_keys == 0
    assert not ((secret
                 and ((result.secret_imported == 0
                       and result.new_signatures != 0)
                      or (result.secret_imported == 1
                          and result.new_signatures > 1)))
                or (not secret and result.new_signatures != 0))
    assert result.new_revocations == 0
    assert not ((secret and result.secret_read != 1 and result.secret_read != 3)
                or (not secret and result.secret_read != 0))
    assert not ((secret and result.secret_imported != 0
                 and result.secret_imported != 1
                 and result.secret_imported != 2)
                or (not secret and result.secret_imported != 0))
    assert not ((secret
                 and ((result.secret_imported == 0
                       and result.secret_unchanged != 1
                       and result.secret_unchanged != 2)
                      or (result.secret_imported == 1
                          and result.secret_unchanged != 0)))
                or (not secret and result.secret_unchanged != 0))
    assert result.not_imported == 0
    if secret:
        assert not (len(result.imports) in (0, 3))
    else:
        assert not (len(result.imports) in (0, 2))

    assert fpr == result.imports[0].fpr
    assert len(result.imports) == 1 or fpr == result.imports[1].fpr
    assert result.imports[0].result == 0

support.init_gpgme(constants.PROTOCOL_OpenPGP)
c = core.Context()

c.op_import(core.Data(file=support.make_filename("pubkey-1.asc")))
result = c.op_import_result()
check_result(result, "ADAB7FCC1F4DE2616ECFA402AF82244F9CD9FD55", False)

c.op_import(core.Data(file=support.make_filename("seckey-1.asc")))
result = c.op_import_result()
check_result(result, "ADAB7FCC1F4DE2616ECFA402AF82244F9CD9FD55", True)
