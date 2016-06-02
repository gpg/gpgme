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

import sys
import os
from pyme import core

def make_filename(name):
    return os.path.join(os.environ['top_srcdir'], 'tests', 'gpg', name)

def init_gpgme(proto):
    core.engine_check_version(proto)

verbose = int(os.environ.get('verbose', 0)) > 1
def print_data(data):
    if verbose:
        data.seek(0, os.SEEK_SET)
        sys.stdout.buffer.write(data.read())
