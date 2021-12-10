# Makefile.am - Makefile for GPGME Cpp tests.
# Copyright (C) 2018 Intevation GmbH
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
# License along with this program; if not, see <https://www.gnu.org/licenses/>.

## Process this file with automake to produce Makefile.in

AM_LDFLAGS = -no-install

LDADD = ../../cpp/src/libgpgmepp.la \
        ../../../src/libgpgme.la @GPG_ERROR_LIBS@ \
        @LDADD_FOR_TESTS_KLUDGE@ -lstdc++

AM_CPPFLAGS = -I$(top_srcdir)/lang/cpp/src -I$(top_builddir)/src \
              @GPG_ERROR_CFLAGS@ @GPG_ERROR_CFLAGS@ \
              @LIBASSUAN_CFLAGS@ -DBUILDING_GPGMEPP \
              -DTOP_SRCDIR="$(top_srcdir)"

run_getkey_SOURCES = run-getkey.cpp
run_keylist_SOURCES = run-keylist.cpp
run_verify_SOURCES = run-verify.cpp
if !HAVE_W32_SYSTEM
run_wkdlookup_SOURCES = run-wkdlookup.cpp
endif

if HAVE_W32_SYSTEM
programs_unix =
else
programs_unix = run-wkdlookup
endif

noinst_PROGRAMS = run-getkey run-keylist run-verify $(programs_unix)
