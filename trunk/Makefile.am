# Copyright (C) 2000 Werner Koch (dd9jn)
# Copyright (C) 2001, 2002 g10 Code GmbH
# 
# This file is part of GPGME.
# 
# GPGME is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# GPGME is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

## Process this file with automake to produce Makefile.in

EXTRA_DIST = README-alpha autogen.sh gpgme.spec.in

if BUILD_ASSUAN
assuan = assuan
else
assuan =
endif

if BUILD_COMPLUS
complus = complus
else
complus = 
endif

if RUN_GPG_TESTS
tests = tests
else
tests = 
endif

SUBDIRS = ${assuan} gpgme ${tests} doc ${complus}

# Fix the version of the spec file and create a file named VERSION 
# to be used for patch's Prereq: feature.
dist-hook:
	@set -e; \
	sed -e 's/@pkg_version@/$(VERSION)/g' \
	    $(top_srcdir)/gpgme.spec.in  > $(distdir)/gpgme.spec
	echo "$(VERSION)" > $(distdir)/VERSION
