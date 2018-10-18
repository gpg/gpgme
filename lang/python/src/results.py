# Robust result objects
#
# Copyright (C) 2016 g10 Code GmbH
#
# This file is part of GPGME.
#
# GPGME is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1 of the
# License, or (at your option) any later version.
#
# GPGME is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General
# Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, see <https://www.gnu.org/licenses/>.

from __future__ import absolute_import, print_function, unicode_literals
del absolute_import, print_function, unicode_literals
"""Robust result objects

Results returned by the underlying library are fragile, i.e. they are
only valid until the next operation is performed in the context.

We cannot arbitrarily constrain the lifetime of Python objects, we
therefore create deep copies of the results.

"""


class Result(object):
    """Result object

    Describes the result of an operation.

    """
    """Convert to types"""
    _type = {}
    """Map functions over list attributes"""
    _map = {}
    """Automatically copy unless blacklisted"""
    _blacklist = {
        'acquire',
        'append',
        'disown',
        'next',
        'own',
        'this',
        'thisown',
    }

    def __init__(self, fragile):
        for key, func in self._type.items():
            if hasattr(fragile, key):
                setattr(self, key, func(getattr(fragile, key)))

        for key, func in self._map.items():
            if hasattr(fragile, key):
                setattr(self, key, list(map(func, getattr(fragile, key))))

        for key in dir(fragile):
            if key.startswith('_') or key in self._blacklist:
                continue
            if hasattr(self, key):
                continue

            setattr(self, key, getattr(fragile, key))

    def __repr__(self):
        return '{}({})'.format(
            self.__class__.__name__,
            ', '.join('{}={!r}'.format(k, getattr(self, k)) for k in dir(self)
                      if not k.startswith('_')))


class InvalidKey(Result):
    pass


class EncryptResult(Result):
    _map = dict(invalid_recipients=InvalidKey)


class Recipient(Result):
    pass


class DecryptResult(Result):
    _type = dict(wrong_key_usage=bool, is_de_vs=bool)
    _map = dict(recipients=Recipient)


class NewSignature(Result):
    pass


class SignResult(Result):
    _map = dict(invalid_signers=InvalidKey, signatures=NewSignature)


class Notation(Result):
    pass


class Signature(Result):
    _type = dict(wrong_key_usage=bool, chain_model=bool, is_de_vs=bool)
    _map = dict(notations=Notation)


class VerifyResult(Result):
    _map = dict(signatures=Signature)


class ImportStatus(Result):
    pass


class ImportResult(Result):
    _map = dict(imports=ImportStatus)


class GenkeyResult(Result):
    _type = dict(primary=bool, sub=bool)


class KeylistResult(Result):
    _type = dict(truncated=bool)


class VFSMountResult(Result):
    pass


class EngineInfo(Result):
    pass
