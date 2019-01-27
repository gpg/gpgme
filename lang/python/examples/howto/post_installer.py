#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (C) 2016-2018 g10 Code GmbH
# Copyright (C) 2015 Ben McGinnes <ben@adversary.org>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA

from __future__ import absolute_import, print_function, unicode_literals

import glob
import os
import os.path
import shutil
import subprocess
import sys
import sysconfig

from shutil import which

del absolute_import, print_function, unicode_literals

try:
    emacs = os.path.realpath(which("emacs"))
except TypeError as e:
    emacs = None

try:
    makeinfo = os.path.realpath(which("makeinfo"))
except TypeError as e:
    makeinfo = None

try:
    pandoc = os.path.realpath(which("pandoc"))
except TypeError as e:
    pandoc = None

try:
    texinfo = os.path.realpath(which("texinfo"))
except TypeError as e:
    texinfo = None

docsrc = glob.glob('doc/src/**/*', recursive=True)

for srcdoc in docsrc:
    process = subprocess.Popen([emacs, srcdoc, "--batch", "-f",
                                "org-texinfo-export-to-texinfo", "--kill"],
                                stdout=subprocess.PIPE)
    procom = process.communicate()

doctexi1 = glob.glob('doc/src/**/*.texi', recursive=True)
doctexi2 = []
doctexi3 = []

for texi in doctexi1:
    doctexi2.append(os.path.realpath(texi))

for texdoc in doctexi2:
    newtex = texdoc.replace("doc/src/", "doc/texinfo/")
    doctexi3.append(newtex)
    with open(texdoc, "r") as f:
        badtex = f.read()
    goodtex = badtex.replace("@documentencoding UTF-8\n",
                             "@documentencoding utf-8\n")
    with open(newtex, "w") as f:
        f.write(goodtex)

for srcdoc in docsrc:
    rstdoc = "{0}.rst".format(srcdoc.replace("doc/src/", "doc/rst/"))
    process = subprocess.Popen([pandoc, "-f", "org", "-t", "rst+smart", "-o",
                                rstdoc, srcdoc], stdout=subprocess.PIPE)
    procom = process.communicate()

with open("doc/rst/index.rst", "r") as f:
    genindex = f.readlines()

indextop = ['.. GPGME Python Bindings documentation master file, created by\n',
            '   sphinx-quickstart on Wed Dec  5 09:04:47 2018.\n',
            '   You can adapt this file completely to your liking, but it should at least\n',
            '   contain the root `toctree` directive.\n', '\n',
            'GPGME Python Bindings\n', '=====================\n', '\n',
            '.. toctree::\n', '   :maxdepth: 3\n', '   :caption: Contents:\n',
            '\n']

with open("doc/rst/index.rst", "w") as f:
    for line in indextop:
        f.write(line)
    for line in genindex[5:]:
        f.write(line)

with open("doc/rst/Makefile", "w") as f:
    f.write("""# Minimal makefile for Sphinx documentation
#

# You can set these variables from the command line.
SPHINXOPTS    =
SPHINXBUILD   = sphinx-build
SOURCEDIR     = .
BUILDDIR      = _build

# Put it first so that "make" without argument is like "make help".
help:
        @$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

.PHONY: help Makefile

# Catch-all target: route all unknown targets to Sphinx using the new
# "make mode" option.  $(O) is meant as a shortcut for $(SPHINXOPTS).
%: Makefile
        @$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)
""")

info_path = os.path.realpath(sysconfig._PREFIX + "/share/info")
info_paths = os.environ["INFOPATH"].split(":")

if info_paths.count(info_path) == 0:
    info_paths.insert(0, info_path)
else:
    pass

for ipath in info_paths:
    if os.path.exists(os.path.realpath(ipath)) is False:
        info_paths.remove(ipath)
    else:
        pass

# Remove the old generated .texi files from the org source directory.
for texifile in doctexi2:
    os.remove(texifile)

print("""
You may now build your preferred documentation format using either:

 1. Sphinx in the doc/rst/ directory; and/or
 2. Texinfo or Makeinfo in the doc/texinfo/ directory.

Alternatively the original Org mode source files can be found in the doc/src/
directory.
""")
