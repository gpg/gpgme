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
# License along with this program; if not, see <http://www.gnu.org/licenses/>.

## Process this file with automake to produce Makefile.in

TESTS_ENVIRONMENT = GNUPGHOME=$(abs_builddir)

TESTS = t-version t-data t-engine-info

EXTRA_DIST = start-stop-agent t-data-1.txt t-data-2.txt ChangeLog-2011

AM_CPPFLAGS = -I$(top_builddir)/src @GPG_ERROR_CFLAGS@
AM_LDFLAGS = -no-install
LDADD = ../src/libgpgme.la @GPG_ERROR_LIBS@

noinst_HEADERS = run-support.h

noinst_PROGRAMS = $(TESTS) run-keylist run-export run-import run-sign \
		  run-verify run-encrypt run-identify run-decrypt run-genkey \
		  run-keysign run-tofu


if RUN_GPG_TESTS
gpgtests = gpg
else
gpgtests =
endif

if RUN_GPGSM_TESTS
gpgsmtests = gpgsm opassuan
else
gpgsmtests =
endif

SUBDIRS = ${gpgtests} ${gpgsmtests}
