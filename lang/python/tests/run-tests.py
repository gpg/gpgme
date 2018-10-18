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
# License along with this program; if not, see <https://www.gnu.org/licenses/>.

from __future__ import absolute_import, division
from __future__ import print_function, unicode_literals

import argparse
import glob
import os
import subprocess
import sys

del absolute_import, division, print_function, unicode_literals


class SplitAndAccumulate(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        current = getattr(namespace, self.dest, list())
        current.extend(values.split())
        setattr(namespace, self.dest, current)


parser = argparse.ArgumentParser(description='Run tests.')
parser.add_argument(
    'tests', metavar='TEST', type=str, nargs='+', help='A test to run')
parser.add_argument(
    '-v', '--verbose', action="store_true", default=False, help='Be verbose.')
parser.add_argument(
    '-q', '--quiet', action="store_true", default=False, help='Be quiet.')
parser.add_argument(
    '--interpreters',
    metavar='PYTHON',
    type=str,
    default=[],
    action=SplitAndAccumulate,
    help='Use these interpreters to run the tests, ' + 'separated by spaces.')
parser.add_argument(
    '--srcdir',
    type=str,
    default=os.environ.get("srcdir", ""),
    help='Location of the tests.')
parser.add_argument(
    '--builddir',
    type=str,
    default=os.environ.get("abs_builddir", ""),
    help='Location of the tests.')
parser.add_argument(
    '--python-libdir',
    type=str,
    default=None,
    help='Optional location of the in-tree module lib directory.')
parser.add_argument(
    '--parallel',
    action="store_true",
    default=False,
    help='Ignored.  For compatibility with run-tests.scm.')

args = parser.parse_args()
if not args.interpreters:
    args.interpreters = [sys.executable]

out = sys.stdout if args.verbose else None
err = sys.stderr if args.verbose else None


def status_to_str(code):
    return {0: "PASS", 77: "SKIP", 99: "ERROR"}.get(code, "FAIL")


results = list()
for interpreter in args.interpreters:
    version = subprocess.check_output([
        interpreter, "-c",
        "import sys; print('{0}.{1}'.format(sys.version_info[0], sys.version_info[1]))"
    ]).strip().decode()

    if args.python_libdir:
        python_libdir = args.python_libdir
    else:
        pattern = os.path.join(args.builddir, "..", "{0}-gpg".format(
            os.path.basename(interpreter)), "lib*")
        libdirs = glob.glob(pattern)
        if len(libdirs) == 0:
            sys.exit(
                "Build directory matching {0!r} not found.".format(pattern))
        elif len(libdirs) > 1:
            sys.exit(
                "Multiple build directories matching {0!r} found: {1}".format(
                    pattern, libdirs))
        python_libdir = libdirs[0]

    env = dict(os.environ)
    env["PYTHONPATH"] = python_libdir

    if not args.quiet:
        print("Running tests using {0} ({1})...".format(interpreter, version))

    for test in args.tests:
        status = subprocess.call(
            [interpreter, os.path.join(args.srcdir, test)],
            env=env,
            stdout=out,
            stderr=err)
        if not args.quiet:
            print("{0}: {1}".format(status_to_str(status), test))
        results.append(status)


def count(status):
    return len(list(filter(lambda x: x == status, results)))


def failed():
    return len(list(filter(lambda x: x not in (0, 77, 99), results)))


if not args.quiet:
    print("{0} tests run, {1} succeeded, {2} failed, {3} skipped.".format(
        len(results), count(0), failed(), count(77)))
    sys.exit(len(results) - count(0) - count(77))
sys.exit(results[0])
