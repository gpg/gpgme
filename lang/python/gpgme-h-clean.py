#!/usr/bin/env python3
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

import sys, re

if len(sys.argv) < 2:
    sys.stderr.write("Usage: %s gpgme.h\n" % sys.argv[0])
    sys.exit(1)

deprec_func=re.compile('^(.*typedef.*|.*\(.*\))\s*_GPGME_DEPRECATED;\s*',re.S)
line_break=re.compile(';|\\$|\\x0c|^\s*#');
try:
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
except IOError as errmsg:
    sys.stderr.write("%s: %s\n" % (sys.argv[0], errmsg))
    sys.exit(1)
