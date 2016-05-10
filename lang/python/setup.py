#!/usr/bin/env python3

# $Id$

# Module: installer
# COPYRIGHT #
# Copyright (C) 2004 Igor Belyi <belyi@users.sourceforge.net>
# Copyright (C) 2002 John Goerzen <jgoerzen@complete.org>
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
# END OF COPYRIGHT #


from distutils.core import setup, Extension
from distutils.command.build_ext import build_ext
import os, os.path, sys
import subprocess

sys.path.append("pyme")
import version

def getconfig(what):
    try:
        process = subprocess.Popen(["gpgme-config", "--%s" % what],
                                   stdout=subprocess.PIPE)
        confdata = process.communicate()[0]
    except OSError as e:
         if e.errno == os.errno.ENOENT:
             raise RuntimeError("Could not call gpgme-config, perhaps install libgpgme-dev")
         else:
             raise
    return [x for x in confdata.decode('utf-8').split() if x != '']

include_dirs = [os.getcwd()]
define_macros = []
library_dirs = []
libs = getconfig('libs')
for item in getconfig('cflags'):
    if item.startswith("-I"):
        include_dirs.append(item[2:])
    elif item.startswith("-D"):
        defitem = item[2:].split("=", 1)
        if len(defitem)==2:
            define_macros.append((defitem[0], defitem[1]))
        else:
            define_macros.append((defitem[0], None))

# Adjust include and library locations in case of win32
uname_s = os.popen("uname -s").read()
if uname_s.startswith("MINGW32"):
   mnts = [x.split()[0:3:2] for x in os.popen("mount").read().split("\n") if x]
   tmplist = sorted([(len(x[1]), x[1], x[0]) for x in mnts])
   tmplist.reverse()
   extra_dirs = []
   for item in include_dirs:
       for ln, mnt, tgt in tmplist:
           if item.startswith(mnt):
               item = os.path.normpath(item[ln:])
               while item[0] == os.path.sep:
                   item = item[1:]
               extra_dirs.append(os.path.join(tgt, item))
               break
   include_dirs += extra_dirs
   for item in [x[2:] for x in libs if x.startswith("-L")]:
       for ln, mnt, tgt in tmplist:
           if item.startswith(mnt):
               item = os.path.normpath(item[ln:])
               while item[0] == os.path.sep:
                   item = item[1:]
               library_dirs.append(os.path.join(tgt, item))
               break

try:
    subprocess.call("swig")
except OSError as e:
    if e.errno == os.errno.ENOENT:
        raise RuntimeError("Could not call swig, perhaps install swig.")
    else:
        raise

subprocess.call(["make swig"], shell=True)

swige = Extension("pyme._pygpgme", ["gpgme_wrap.c", "helpers.c"],
                  include_dirs = include_dirs,
                  define_macros = define_macros,
                  library_dirs = library_dirs,
                  extra_link_args = libs)

setup(name = "pyme",
      version = version.versionstr,
      description = version.description,
      author = version.author,
      author_email = version.author_email,
      url = version.homepage,
      ext_modules=[swige],
      packages = ['pyme', 'pyme.constants', 'pyme.constants.data',
                  'pyme.constants.keylist', 'pyme.constants.sig'],
      license = version.copyright + \
                ", Licensed under the GPL version 2 and the LGPL version 2.1"
)

