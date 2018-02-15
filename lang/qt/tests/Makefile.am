# Makefile.am - Makefile for GPGME Qt tests.
# Copyright (C) 2016 Bundesamt für Sicherheit in der Informationstechnik
# Software engineering by Intevation GmbH
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

TESTS = initial.test t-keylist t-keylocate t-ownertrust t-tofuinfo \
        t-encrypt t-verify t-various t-config

moc_files = t-keylist.moc t-keylocate.moc t-ownertrust.moc t-tofuinfo.moc \
            t-encrypt.moc t-support.hmoc t-wkspublish.moc t-verify.moc \
            t-various.moc t-config.moc

AM_LDFLAGS = -no-install

LDADD = ../../cpp/src/libgpgmepp.la ../src/libqgpgme.la \
        ../../../src/libgpgme.la @GPGME_QT_LIBS@ @GPG_ERROR_LIBS@ \
        @GPGME_QTTEST_LIBS@ -lstdc++

AM_CPPFLAGS = -I$(top_srcdir)/lang/cpp/src -I$(top_builddir)/src \
              @GPG_ERROR_CFLAGS@ @GPGME_QT_CFLAGS@ @GPG_ERROR_CFLAGS@ \
              @LIBASSUAN_CFLAGS@ @GPGME_QTTEST_CFLAGS@ -DBUILDING_QGPGME \
              -I$(top_srcdir)/lang/qt/src \
              -DTOP_SRCDIR="$(top_srcdir)"

support_src = t-support.h t-support.cpp

t_keylist_SOURCES = t-keylist.cpp $(support_src)
t_keylocate_SOURCES = t-keylocate.cpp $(support_src)
t_ownertrust_SOURCES = t-ownertrust.cpp $(support_src)
t_tofuinfo_SOURCES = t-tofuinfo.cpp $(support_src)
t_encrypt_SOURCES = t-encrypt.cpp $(support_src)
t_wkspublish_SOURCES = t-wkspublish.cpp $(support_src)
t_verify_SOURCES = t-verify.cpp $(support_src)
t_various_SOURCES = t-various.cpp $(support_src)
t_config_SOURCES = t-config.cpp $(support_src)
run_keyformailboxjob_SOURCES = run-keyformailboxjob.cpp

nodist_t_keylist_SOURCES = $(moc_files)

BUILT_SOURCES = $(moc_files) pubring-stamp

noinst_PROGRAMS = t-keylist t-keylocate t-ownertrust t-tofuinfo t-encrypt \
    run-keyformailboxjob t-wkspublish t-verify t-various t-config

CLEANFILES = secring.gpg pubring.gpg pubring.kbx trustdb.gpg dirmngr.conf \
	gpg-agent.conf pubring.kbx~ S.gpg-agent gpg.conf pubring.gpg~ \
	random_seed S.gpg-agent .gpg-v21-migrated pubring-stamp $(moc_files) \
	gpg.conf tofu.db

clean-local:
	-$(TESTS_ENVIRONMENT) $(top_srcdir)/tests/start-stop-agent --stop
	-rm -fR  private-keys-v1.d crls.d

pubring-stamp: $(top_srcdir)/tests/gpg/pubdemo.asc \
	             $(top_srcdir)/tests/gpg/secdemo.asc
	-$(TESTS_ENVIRONMENT) gpgconf --kill all
	echo "ignore-invalid-option allow-loopback-pinentry" > $(abs_builddir)/gpg-agent.conf
	echo "allow-loopback-pinentry" >> gpg-agent.conf
	echo "ignore-invalid-option pinentry-mode" > gpg.conf
	echo "pinentry-mode loopback" >> gpg.conf
	$(TESTS_ENVIRONMENT) $(GPG) --no-permission-warning \
           --import $(top_srcdir)/tests/gpg/pubdemo.asc
	$(TESTS_ENVIRONMENT) $(GPG) --no-permission-warning \
		   --passphrase "abc" \
           --import $(top_srcdir)/tests/gpg/secdemo.asc
	touch pubring-stamp

.cpp.moc:
	$(MOC) `test -f '$<' || echo '$(srcdir)/'`$< -o $@

.h.hmoc:
	$(MOC) `test -f '$<' || echo '$(srcdir)/'`$< -o $@
