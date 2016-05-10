# Makefile.am - Makefile for GPGME Qt tests.
# Copyright (C) 2016 Intevation GmbH
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

GPG = gpg

TESTS_ENVIRONMENT = GNUPGHOME=$(abs_builddir)

EXTRA_DIST = initial.test

TESTS = initial.test t-keylist

moc_files = t-keylist.moc

AM_LDFLAGS = -no-install

LDADD = ../../cpp/src/libgpgmepp.la ../src/libqgpgme.la \
        ../../../src/libgpgme.la @GPGME_QT_LIBS@ @GPG_ERROR_LIBS@ \
        @GPGME_QTTEST_LIBS@

AM_CPPFLAGS = -I$(top_builddir)/src @GPG_ERROR_CFLAGS@ \
              @GPGME_QT_CFLAGS@ @GPG_ERROR_CFLAGS@ @LIBASSUAN_CFLAGS@ \
              @GPGME_QTTEST_CFLAGS@ \
              -I$(top_srcdir)/lang/cpp/src -I$(top_srcdir)/lang/qt/src \
              -DTOP_SRCDIR="$(top_srcdir)"

check-local: ./pubring-stamp

# To guarantee that check-local is run before any tests we
# add this dependency:
initial.test : check-local

t_keylist_SOURCES = t-keylist.cpp

nodist_t_keylist_SOURCES = $(moc_files)

BUILT_SOURCES = $(moc_files)

noinst_PROGRAMS = t-keylist

CLEANFILES = secring.gpg pubring.gpg pubring.kbx trustdb.gpg dirmngr.conf \
	gpg-agent.conf pubring.kbx~ S.gpg-agent gpg.conf pubring.gpg~ \
	random_seed S.gpg-agent .gpg-v21-migrated pubring-stamp $(moc_files)

export GNUPGHOME := $(abs_builddir)

./pubring-stamp: $(top_srcdir)/tests/gpg/pubdemo.asc \
	             $(top_srcdir)/tests/gpg/secdemo.asc
	$(GPG) --no-permission-warning \
           --import $(top_srcdir)/tests/gpg/pubdemo.asc
	$(GPG) --no-permission-warning \
           --import $(top_srcdir)/tests/gpg/secdemo.asc
	touch ./pubring-stamp

.cpp.moc:
	$(MOC) `test -f '$<' || echo '$(srcdir)/'`$< -o $@
