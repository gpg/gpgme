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

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import glob
import os
import subprocess
import sys

class SplitAndAccumulate(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        current = getattr(namespace, self.dest, list())
        current.extend(values.split())
        setattr(namespace, self.dest, current)

parser = argparse.ArgumentParser(description='Run tests.')
parser.add_argument('tests', metavar='TEST', type=str, nargs='+',
                    help='A test to run')
parser.add_argument('-v', '--verbose', action="store_true", default=False,
                    help='Be verbose.')
parser.add_argument('--interpreters', metavar='PYTHON', type=str,
                    default=[], action=SplitAndAccumulate,
                    help='Use these interpreters to run the tests, ' +
                    'separated by spaces.')
parser.add_argument('--srcdir', type=str,
                    default=os.environ.get("srcdir", ""),
                    help='Location of the tests.')
parser.add_argument('--builddir', type=str,
                    default=os.environ.get("abs_builddir", ""),
                    help='Location of the tests.')

args = parser.parse_args()
if not args.interpreters:
    args.interpreters = [sys.executable]

out = sys.stdout if args.verbose else None
err = sys.stderr if args.verbose else None

def status_to_str(code):
    return {0: "PASS", 77: "SKIP", 99: "ERROR"}.get(code, "FAIL")

results = list()
for interpreter in args.interpreters:
    version = subprocess.check_output(
        [interpreter, "-c", "import sys; print('{0}.{1}'.format(sys.version_info[0], sys.version_info[1]))"]).strip().decode()

    builddirs = glob.glob(os.path.join(args.builddir, "..", "build",
                                       "lib*"+version))
    assert len(builddirs) == 1, \
        "Expected one build directory, got {0}".format(builddirs)
    env = dict(os.environ)
    env["PYTHONPATH"] = builddirs[0]

    print("Running tests using {0} ({1})...".format(interpreter, version))
    for test in args.tests:
        status = subprocess.call(
            [interpreter, os.path.join(args.srcdir, test)],
            env=env, stdout=out, stderr=err)
        print("{0}: {1}".format(status_to_str(status), test))
        results.append(status)

def count(status):
    return len(list(filter(lambda x: x == status, results)))
def failed():
    return len(list(filter(lambda x: x not in (0, 77, 99), results)))

print("{0} tests run, {1} succeeded, {2} failed, {3} skipped.".format(
    len(results), count(0), failed(), count(77)))
sys.exit(len(results) - count(0))
