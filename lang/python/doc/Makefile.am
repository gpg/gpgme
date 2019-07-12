# Makefile.am for the Python bindings.
# Copyright (C) 2019 g10 Code GmbH
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
# License along with this program; if not, see <https://gnu.org/licenses/>.
# SPDX-License-Identifier: LGPL-2.1-or-later

EXTRA_DIST = README \
             rst/_build/README \
             rst/_static/README \
             rst/_templates/README \
             rst/conf.py \
             rst/gpgme-python-howto.rst \
             rst/index.rst \
             rst/maintenance-mode.rst \
             rst/short-history.rst \
             rst/what-is-new.rst \
             rst/what-was-new.rst \
             src/gpgme-python-howto.org \
             src/index.org \
             src/maintenance-mode.org \
             src/short-history.org \
             src/what-is-new.org \
             src/what-was-new.org \
             texinfo/texinfo.tex \
             texinfo/gpgme-python-howto.texi \
             texinfo/index.texi \
             texinfo/maintenance-mode.texi \
             texinfo/short-history.texi \
             texinfo/what-is-new.texi \
             texinfo/what-was-new.texi

if MAINTAINER_MODE
dist-hook: the_doc_dirs $(RST_GENERATED) $(TEXI_GENERATED)
	cp $(RST_GENERATED) rst/
	cp $(TEXI_GENERATED) texinfo/

.org.rst:
	pandoc -f org -t rst $< -o $@

.org.texi:
	pandoc -f org -t texinfo $< -o $@

RST_GENERATED = src/gpgme-python-howto.rst src/index.rst \
	src/maintenance-mode.rst src/short-history.rst src/what-is-new.rst \
	src/what-was-new.rst

TEXI_GENERATED = src/gpgme-python-howto.texi src/index.texi \
	src/maintenance-mode.texi src/short-history.texi src/what-is-new.texi \
	src/what-was-new.texi

# make 'src', 'rst' and 'texinfo' dir in build directory
.PHONY: the_doc_dirs
the_doc_dirs:
	if test ! -d src; then $(MKDIR_P) src; fi
	if test ! -d rst; then $(MKDIR_P) rst; fi
	if test ! -d texinfo; then $(MKDIR_P) texinfo; fi
endif

MAINTAINERCLEANFILES = $(RST_GENERATED) $(TEXI_GENERATED)
