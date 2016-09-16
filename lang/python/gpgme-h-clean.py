#!/usr/bin/env python

# Copyright (C) 2016 g10 Code GmbH
# Copyright (C) 2004,2008 Igor Belyi <belyi@users.sourceforge.net>
#
#    This library is free software; you can redistribute it and/or
#    modify it under the terms of the GNU Lesser General Public
#    License as published by the Free Software Foundation; either
#    version 2.1 of the License, or (at your option) any later version.
#
#    This library is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#    Lesser General Public License for more details.
#
#    You should have received a copy of the GNU Lesser General Public
#    License along with this library; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA

from __future__ import absolute_import, print_function, unicode_literals
del absolute_import, print_function, unicode_literals

import sys, re

if len(sys.argv) != 2:
    sys.stderr.write("Usage: %s path/to/[gpgme|gpg-error].h\n" % sys.argv[0])
    sys.exit(1)

deprec_func = re.compile(r'^(.*typedef.*|.*\(.*\)|[^#]+\s+.+)'
                         + r'\s*_GPGME_DEPRECATED(_OUTSIDE_GPGME)?\(.*\);\s*',
                         re.S)
line_break = re.compile(';|\\$|\\x0c|^\s*#|{');

if 'gpgme.h' in sys.argv[1]:
    gpgme = open(sys.argv[1])
    tmp = gpgme.readline()
    text = ''
    while tmp:
        text += re.sub(' class ', ' _py_obsolete_class ', tmp)
        if line_break.search(tmp):
            if not deprec_func.search(text):
                sys.stdout.write(text)
            text = ''
        tmp = gpgme.readline()
    sys.stdout.write(text)
    gpgme.close()
else:
    filter_re = re.compile(r'GPG_ERR_[^ ]* =')
    rewrite_re = re.compile(r' *(.*) = .*')
    for line in open(sys.argv[1]):
        if not filter_re.search(line):
            continue
        print(rewrite_re.sub(r'%constant long \1 = \1;', line.strip()))
