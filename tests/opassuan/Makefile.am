# Copyright (C) 2009 g10 Code GmbH
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
# License along with this program; if not, see <http://www.gnu.org/licenses/>.

## Process this file with automake to produce Makefile.in

TESTS_ENVIRONMENT = GNUPGHOME=$(abs_builddir) GPG_AGENT_INFO=

noinst_HEADERS =
TESTS =

EXTRA_DIST =

AM_CPPFLAGS = -I$(top_builddir)/src @GPG_ERROR_CFLAGS@
LDADD = ../../src/libgpgme.la

noinst_PROGRAMS = $(TESTS) t-command

DISTCLEANFILES =

