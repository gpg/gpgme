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
# License along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

## Process this file with automake to produce Makefile.in

TESTS_ENVIRONMENT = GNUPGHOME=$(abs_builddir)

TESTS = t-version t-data t-engine-info

EXTRA_DIST = t-data-1.txt t-data-2.txt

INCLUDES = -I$(top_builddir)/src

AM_CPPFLAGS = @GPG_ERROR_CFLAGS@
LDADD = ../src/libgpgme.la @GPG_ERROR_LIBS@

noinst_PROGRAMS = $(TESTS)

if RUN_GPG_TESTS
gpgtests = gpg
else
gpgtests = 
endif

if RUN_GPGSM_TESTS
gpgsmtests = gpgsm
else
gpgsmtests = 
endif

SUBDIRS = ${gpgtests} ${gpgsmtests}
