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
# License along with this program; if not, see <https://www.gnu.org/licenses/>.

from __future__ import absolute_import, print_function, unicode_literals

import contextlib
import shutil
import sys
import os
import re
import tempfile
import time
import gpg

del absolute_import, print_function, unicode_literals


def assert_gpg_version(version=(2, 1, 0)):
    with gpg.Context() as c:
        clean_version = re.match(r'\d+\.\d+\.\d+',
                                 c.engine_info.version).group(0)
        if tuple(map(int, clean_version.split('.'))) < version:
            print("GnuPG too old: have {0}, need {1}.".format(
                c.engine_info.version, '.'.join(map(str, version))))
            sys.exit(77)

def is_gpg_version(version):
    with gpg.Context() as c:
        clean_version = re.match(r'\d+\.\d+\.\d+',
                                 c.engine_info.version).group(0)
        return tuple(map(int, clean_version.split('.'))) == version


def have_tofu_support(ctx, some_uid):
    keys = list(
        ctx.keylist(
            some_uid,
            mode=(gpg.constants.keylist.mode.LOCAL |
                  gpg.constants.keylist.mode.WITH_TOFU)))
    return len(keys) > 0


# Skip the Python tests for GnuPG < 2.1.12.  Prior versions do not
# understand the command line flags that we assume exist.  C.f. issue
# 3008.
assert_gpg_version((2, 1, 12))

# known keys
alpha = "A0FF4590BB6122EDEF6E3C542D727CC768697734"
bob = "D695676BDCEDCC2CDD6152BCFE180B1DA9E3B0B2"
encrypt_only = "F52770D5C4DB41408D918C9F920572769B9FE19C"
sign_only = "7CCA20CCDE5394CEE71C9F0BFED153F12F18F45D"
no_such_key = "A" * 40


def make_filename(name):
    return os.path.join(os.environ['top_srcdir'], 'tests', name)


def in_srcdir(name):
    return os.path.join(os.environ['srcdir'], name)


verbose = int(os.environ.get('verbose', 0)) > 1


def print_data(data):
    if verbose:
        try:
            # See if it is a file-like object.
            data.seek(0, os.SEEK_SET)
            data = data.read()
        except:
            # Hope for the best.
            pass

        if hasattr(sys.stdout, "buffer"):
            sys.stdout.buffer.write(data)
        else:
            sys.stdout.write(data)


def mark_key_trusted(ctx, key):
    class Editor(object):
        def __init__(self):
            self.steps = ["trust", "save"]

        def edit(self, status, args, out):
            if args == "keyedit.prompt":
                result = self.steps.pop(0)
            elif args == "edit_ownertrust.value":
                result = "5"
            elif args == "edit_ownertrust.set_ultimate.okay":
                result = "Y"
            elif args == "keyedit.save.okay":
                result = "Y"
            else:
                result = None
            return result

    with gpg.Data() as sink:
        ctx.op_edit(key, Editor().edit, sink, sink)


# Python3.2 and up has tempfile.TemporaryDirectory, but we cannot use
# that, because there shutil.rmtree is used without
# ignore_errors=True, and that races against gpg-agent deleting its
# sockets.
class TemporaryDirectory(object):
    def __enter__(self):
        self.path = tempfile.mkdtemp()
        return self.path

    def __exit__(self, *args):
        shutil.rmtree(self.path, ignore_errors=True)


@contextlib.contextmanager
def EphemeralContext():
    with TemporaryDirectory() as tmp:
        home = os.environ['GNUPGHOME']
        shutil.copy(os.path.join(home, "gpg.conf"), tmp)
        shutil.copy(os.path.join(home, "gpg-agent.conf"), tmp)

        with gpg.Context(home_dir=tmp) as ctx:
            yield ctx

            # Ask the agent to quit.
            agent_socket = os.path.join(tmp, "S.gpg-agent")
            ctx.protocol = gpg.constants.protocol.ASSUAN
            ctx.set_engine_info(ctx.protocol, file_name=agent_socket)
            try:
                ctx.assuan_transact(["KILLAGENT"])
            except gpg.errors.GPGMEError as e:
                if e.getcode() == gpg.errors.ASS_CONNECT_FAILED:
                    pass  # the agent was not running
                else:
                    raise

            # Block until it is really gone.
            while os.path.exists(agent_socket):
                time.sleep(.01)
