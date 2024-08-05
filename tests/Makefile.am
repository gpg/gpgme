# Makefile.am - Makefile for GPGME tests.
# Copyright (C) 2000 Werner Koch (dd9jn)
# Copyright (C) 2001, 2004 g10 Code GmbH
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

## Process this file with automake to produce Makefile.in

GNUPGHOME=$(abs_builddir)
TESTS_ENVIRONMENT = GNUPGHOME=$(GNUPGHOME)

TESTS = t-version t-data t-engine-info

EXTRA_DIST = start-stop-agent t-data-1.txt t-data-2.txt ChangeLog-2011

AM_CPPFLAGS = -I$(top_builddir)/src @GPG_ERROR_CFLAGS@

if HAVE_W32_SYSTEM
AM_LDFLAGS = -no-fast-install
else
AM_LDFLAGS = -no-install
endif

LDADD = ../src/libgpgme.la @GPG_ERROR_LIBS@ @LDADD_FOR_TESTS_KLUDGE@

noinst_HEADERS = run-support.h

noinst_PROGRAMS = $(TESTS) run-keylist run-export run-import run-sign \
		  run-verify run-encrypt run-identify run-decrypt run-genkey \
		  run-keysign run-tofu run-swdb run-threaded \
		  run-receive-keys run-setownertrust

run_threaded_CPPFLAGS = -I$(top_builddir)/src @GPG_ERROR_MT_CFLAGS@
run_threaded_LDADD = ../src/libgpgme.la \
		     @GPG_ERROR_MT_LIBS@ @LDADD_FOR_TESTS_KLUDGE@

if RUN_GPG_TESTS
gpgtests = gpg json
else
gpgtests =
endif

if RUN_GPGSM_TESTS
gpgsmtests = gpgsm opassuan
else
gpgsmtests =
endif

SUBDIRS = ${gpgtests} ${gpgsmtests}
