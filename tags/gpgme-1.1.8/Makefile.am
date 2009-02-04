# Makefile.am - Top level Makefile for GPGME.
# Copyright (C) 2000 Werner Koch (dd9jn)
# Copyright (C) 2001, 2002, 2004, 2005, 2008 g10 Code GmbH
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
# License along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

## Process this file with automake to produce Makefile.in

ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = dist-bzip2

EXTRA_DIST = gpgme.spec.in autogen.sh 

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

SUBDIRS = ${assuan} src ${tests} doc ${complus} lang

# Fix the version of the spec file and create a file named VERSION 
# to be used for patch's Prereq: feature.
dist-hook:
	@set -e; \
	sed -e 's/@pkg_version@/$(VERSION)/g' \
	    $(top_srcdir)/gpgme.spec.in  > $(distdir)/gpgme.spec
	echo "$(VERSION)" > $(distdir)/VERSION
