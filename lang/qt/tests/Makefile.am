# Makefile.am - Makefile for QGpgME tests.
# Copyright (C) 2016 Bundesamt für Sicherheit in der Informationstechnik
# Software engineering by Intevation GmbH
#
# This file is part of QGpgME.
#
# QGpgME is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# QGpgME is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <https://gnu.org/licenses/>.
# SPDX-License-Identifier: GPL-2.0-or-later

## Process this file with automake to produce Makefile.in

GPG = gpg

GNUPGHOME=$(abs_builddir)
TESTS_ENVIRONMENT = GNUPGHOME=$(GNUPGHOME)

EXTRA_DIST = initial.test final.test

if WANT_QT5
the_tests5 = \
	t-addexistingsubkey5 \
	t-changeexpiryjob5 \
	t-config5 \
	t-decryptverify5 \
	t-disablekey5 \
	t-encrypt5 \
	t-import5 \
	t-keylist5 \
	t-keylocate5 \
	t-ownertrust5 \
	t-remarks5 \
	t-revokekey5 \
	t-setprimaryuserid5 \
	t-tofuinfo5 \
	t-trustsignatures5 \
	t-various5 \
	t-verify5 \
	t-wkdlookup5
# disabled test: t-wkspublish5
the_runners5 = \
	run-decryptverifyarchivejob5 \
	run-decryptverifyjob5 \
	run-encryptarchivejob5 \
	run-encryptjob5 \
	run-exportjob5 \
	run-importjob5 \
	run-keyformailboxjob5 \
	run-receivekeysjob5 \
	run-refreshkeysjob5 \
	run-signarchivejob5 \
	run-signjob5 \
	run-verifydetachedjob5 \
	run-verifyopaquejob5 \
	run-wkdrefreshjob5
endif
if WANT_QT6
the_tests6 = \
	t-addexistingsubkey6 \
	t-changeexpiryjob6 \
	t-config6 \
	t-decryptverify6 \
	t-disablekey6 \
	t-encrypt6 \
	t-import6 \
	t-keylist6 \
	t-keylocate6 \
	t-ownertrust6 \
	t-remarks6 \
	t-revokekey6 \
	t-setprimaryuserid6 \
	t-tofuinfo6 \
	t-trustsignatures6 \
	t-various6 \
	t-verify6 \
	t-wkdlookup6
# disabled test: t-wkspublish6
the_runners6 = \
	run-decryptverifyarchivejob6 \
	run-decryptverifyjob6 \
	run-encryptarchivejob6 \
	run-encryptjob6 \
	run-exportjob6 \
	run-importjob6 \
	run-keyformailboxjob6 \
	run-receivekeysjob6 \
	run-refreshkeysjob6 \
	run-signarchivejob6 \
	run-signjob6 \
	run-verifydetachedjob6 \
	run-verifyopaquejob6 \
	run-wkdrefreshjob6
endif

TESTS = initial.test $(the_tests5) $(the_tests6) final.test

# define .moc files for all tests; we'll moc their .cpp files
# the only header that needs to be moc'd (t-support.h) is handled individually
# moc_files = $(the_tests:%=%.moc)

# generate the moc files in two steps:
# 1. generate Qt 5/6-specific moc files in builddir with extension .moc5/.moc6;
#    this ensures correct dependencies on the source files
# 2. generate forwarding headers in subfolders moc5/moc6 with extension .moc;
#    this ensures that the "foo.moc" includes in the source files work and
#    include the correct version of the generated moc files for Qt 5/6
# GNU make's pattern rules would make this easier, but we don't want to use them
if WANT_QT5
moc5_dir = moc5
moc5_files = $(moc5_dir)/t-support.hmoc $(the_tests5:%5=%.moc5)
moc5_forward_headers = $(the_tests5:%5=$(moc5_dir)/%.moc)

$(moc5_dir)/t-support.hmoc: t-support.h | $(moc5_dir)
	$(MOC5) `test -f '$<' || echo '$(srcdir)/'`$< -o $@

.cpp.moc5:
	$(MOC5) `test -f '$<' || echo '$(srcdir)/'`$< -o $@

$(moc5_dir):
	mkdir $(moc5_dir)

$(moc5_forward_headers): Makefile.am | $(moc5_dir)
	echo "#include \"../$(notdir $@)5\"" > "$@"
endif
if WANT_QT6
moc6_dir = moc6
moc6_files = $(moc6_dir)/t-support.hmoc $(the_tests6:%6=%.moc6)
moc6_forward_headers = $(the_tests6:%6=$(moc6_dir)/%.moc)

$(moc6_dir)/t-support.hmoc: t-support.h | $(moc6_dir)
	$(MOC6) `test -f '$<' || echo '$(srcdir)/'`$< -o $@

.cpp.moc6:
	$(MOC6) `test -f '$<' || echo '$(srcdir)/'`$< -o $@

$(moc6_dir):
	mkdir $(moc6_dir)

$(moc6_forward_headers): Makefile.am | $(moc6_dir)
	echo "#include \"../$(notdir $@)6\"" > "$@"
endif

AM_LDFLAGS = -no-install

if WANT_QT5
ldadd_qt5 = ../../cpp/src/libgpgmepp.la ../src/libqgpgme.la \
        ../../../src/libgpgme.la @GPGME_QT5_LIBS@ @GPG_ERROR_LIBS@ \
        @GPGME_QT5TEST_LIBS@ @LDADD_FOR_TESTS_KLUDGE@ -lstdc++

cppflags_qt5 = -I$(moc5_dir) -I$(top_srcdir)/lang/qt/src -I$(top_builddir)/lang/cpp/src \
              -I$(top_builddir)/src \
              @GPG_ERROR_CFLAGS@ @GPGME_QT5_CFLAGS@ @GPG_ERROR_CFLAGS@ \
              @LIBASSUAN_CFLAGS@ @GPGME_QT5TEST_CFLAGS@ -DBUILDING_QGPGME \
              -DTOP_SRCDIR="$(top_srcdir)"
endif
if WANT_QT6
ldadd_qt6 = ../../cpp/src/libgpgmepp.la ../src/libqgpgmeqt6.la \
        ../../../src/libgpgme.la @GPGME_QT6_LIBS@ @GPG_ERROR_LIBS@ \
        @GPGME_QT6TEST_LIBS@ @LDADD_FOR_TESTS_KLUDGE@ -lstdc++

cppflags_qt6 = -I$(moc6_dir) -I$(top_srcdir)/lang/qt/src -I$(top_builddir)/lang/cpp/src \
              -I$(top_builddir)/src \
              @GPG_ERROR_CFLAGS@ @GPGME_QT6_CFLAGS@ @GPG_ERROR_CFLAGS@ \
              @LIBASSUAN_CFLAGS@ @GPGME_QT6TEST_CFLAGS@ -DBUILDING_QGPGME \
              -DTOP_SRCDIR="$(top_srcdir)"
endif

support_src = t-support.h t-support.cpp

if WANT_QT5
t_addexistingsubkey5_SOURCES = t-addexistingsubkey.cpp $(support_src)
t_addexistingsubkey5_LDADD = $(ldadd_qt5)
t_addexistingsubkey5_CPPFLAGS = $(cppflags_qt5)
t_changeexpiryjob5_SOURCES = t-changeexpiryjob.cpp $(support_src)
t_changeexpiryjob5_LDADD = $(ldadd_qt5)
t_changeexpiryjob5_CPPFLAGS = $(cppflags_qt5)
t_config5_SOURCES = t-config.cpp $(support_src)
t_config5_LDADD = $(ldadd_qt5)
t_config5_CPPFLAGS = $(cppflags_qt5)
t_decryptverify5_SOURCES = t-decryptverify.cpp $(support_src)
t_decryptverify5_LDADD = $(ldadd_qt5)
t_decryptverify5_CPPFLAGS = $(cppflags_qt5)
t_disablekey5_SOURCES = t-disablekey.cpp $(support_src)
t_disablekey5_LDADD = $(ldadd_qt5)
t_disablekey5_CPPFLAGS = $(cppflags_qt5)
t_encrypt5_SOURCES = t-encrypt.cpp $(support_src)
t_encrypt5_LDADD = $(ldadd_qt5)
t_encrypt5_CPPFLAGS = $(cppflags_qt5)
t_import5_SOURCES = t-import.cpp $(support_src)
t_import5_LDADD = $(ldadd_qt5)
t_import5_CPPFLAGS = $(cppflags_qt5)
t_keylist5_SOURCES = t-keylist.cpp $(support_src)
t_keylist5_LDADD = $(ldadd_qt5)
t_keylist5_CPPFLAGS = $(cppflags_qt5)
t_keylocate5_SOURCES = t-keylocate.cpp $(support_src)
t_keylocate5_LDADD = $(ldadd_qt5)
t_keylocate5_CPPFLAGS = $(cppflags_qt5)
t_ownertrust5_SOURCES = t-ownertrust.cpp $(support_src)
t_ownertrust5_LDADD = $(ldadd_qt5)
t_ownertrust5_CPPFLAGS = $(cppflags_qt5)
t_remarks5_SOURCES = t-remarks.cpp $(support_src)
t_remarks5_LDADD = $(ldadd_qt5)
t_remarks5_CPPFLAGS = $(cppflags_qt5)
t_revokekey5_SOURCES = t-revokekey.cpp $(support_src)
t_revokekey5_LDADD = $(ldadd_qt5)
t_revokekey5_CPPFLAGS = $(cppflags_qt5)
t_setprimaryuserid5_SOURCES = t-setprimaryuserid.cpp $(support_src)
t_setprimaryuserid5_LDADD = $(ldadd_qt5)
t_setprimaryuserid5_CPPFLAGS = $(cppflags_qt5)
t_tofuinfo5_SOURCES = t-tofuinfo.cpp $(support_src)
t_tofuinfo5_LDADD = $(ldadd_qt5)
t_tofuinfo5_CPPFLAGS = $(cppflags_qt5)
t_trustsignatures5_SOURCES = t-trustsignatures.cpp $(support_src)
t_trustsignatures5_LDADD = $(ldadd_qt5)
t_trustsignatures5_CPPFLAGS = $(cppflags_qt5)
t_various5_SOURCES = t-various.cpp $(support_src)
t_various5_LDADD = $(ldadd_qt5)
t_various5_CPPFLAGS = $(cppflags_qt5)
t_verify5_SOURCES = t-verify.cpp $(support_src)
t_verify5_LDADD = $(ldadd_qt5)
t_verify5_CPPFLAGS = $(cppflags_qt5)
t_wkdlookup5_SOURCES = t-wkdlookup.cpp $(support_src)
t_wkdlookup5_LDADD = $(ldadd_qt5)
t_wkdlookup5_CPPFLAGS = $(cppflags_qt5)
# t_wkspublish5_SOURCES = t-wkspublish.cpp $(support_src)
# t_wkspublish5_LDADD = $(ldadd_qt5)
# t_wkspublish5_CPPFLAGS = $(cppflags_qt5)
run_decryptverifyarchivejob5_SOURCES = run-decryptverifyarchivejob.cpp
run_decryptverifyarchivejob5_LDADD = $(ldadd_qt5)
run_decryptverifyarchivejob5_CPPFLAGS = $(cppflags_qt5)
run_decryptverifyjob5_SOURCES = run-decryptverifyjob.cpp
run_decryptverifyjob5_LDADD = $(ldadd_qt5)
run_decryptverifyjob5_CPPFLAGS = $(cppflags_qt5)
run_encryptarchivejob5_SOURCES = run-encryptarchivejob.cpp
run_encryptarchivejob5_LDADD = $(ldadd_qt5)
run_encryptarchivejob5_CPPFLAGS = $(cppflags_qt5)
run_encryptjob5_SOURCES = run-encryptjob.cpp
run_encryptjob5_LDADD = $(ldadd_qt5)
run_encryptjob5_CPPFLAGS = $(cppflags_qt5)
run_exportjob5_SOURCES = run-exportjob.cpp
run_exportjob5_LDADD = $(ldadd_qt5)
run_exportjob5_CPPFLAGS = $(cppflags_qt5)
run_importjob5_SOURCES = run-importjob.cpp
run_importjob5_LDADD = $(ldadd_qt5)
run_importjob5_CPPFLAGS = $(cppflags_qt5)
run_keyformailboxjob5_SOURCES = run-keyformailboxjob.cpp
run_keyformailboxjob5_LDADD = $(ldadd_qt5)
run_keyformailboxjob5_CPPFLAGS = $(cppflags_qt5)
run_receivekeysjob5_SOURCES = run-receivekeysjob.cpp
run_receivekeysjob5_LDADD = $(ldadd_qt5)
run_receivekeysjob5_CPPFLAGS = $(cppflags_qt5)
run_refreshkeysjob5_SOURCES = run-refreshkeysjob.cpp
run_refreshkeysjob5_LDADD = $(ldadd_qt5)
run_refreshkeysjob5_CPPFLAGS = $(cppflags_qt5)
run_signarchivejob5_SOURCES = run-signarchivejob.cpp
run_signarchivejob5_LDADD = $(ldadd_qt5)
run_signarchivejob5_CPPFLAGS = $(cppflags_qt5)
run_signjob5_SOURCES = run-signjob.cpp
run_signjob5_LDADD = $(ldadd_qt5)
run_signjob5_CPPFLAGS = $(cppflags_qt5)
run_verifydetachedjob5_SOURCES = run-verifydetachedjob.cpp
run_verifydetachedjob5_LDADD = $(ldadd_qt5)
run_verifydetachedjob5_CPPFLAGS = $(cppflags_qt5)
run_verifyopaquejob5_SOURCES = run-verifyopaquejob.cpp
run_verifyopaquejob5_LDADD = $(ldadd_qt5)
run_verifyopaquejob5_CPPFLAGS = $(cppflags_qt5)
run_wkdrefreshjob5_SOURCES = run-wkdrefreshjob.cpp
run_wkdrefreshjob5_LDADD = $(ldadd_qt5)
run_wkdrefreshjob5_CPPFLAGS = $(cppflags_qt5)

#nodist_t_keylist5_SOURCES = $(moc5_files) $(moc5_forward_headers)
endif
if WANT_QT6
t_addexistingsubkey6_SOURCES = t-addexistingsubkey.cpp $(support_src)
t_addexistingsubkey6_LDADD = $(ldadd_qt6)
t_addexistingsubkey6_CPPFLAGS = $(cppflags_qt6)
t_changeexpiryjob6_SOURCES = t-changeexpiryjob.cpp $(support_src)
t_changeexpiryjob6_LDADD = $(ldadd_qt6)
t_changeexpiryjob6_CPPFLAGS = $(cppflags_qt6)
t_config6_SOURCES = t-config.cpp $(support_src)
t_config6_LDADD = $(ldadd_qt6)
t_config6_CPPFLAGS = $(cppflags_qt6)
t_decryptverify6_SOURCES = t-decryptverify.cpp $(support_src)
t_decryptverify6_LDADD = $(ldadd_qt6)
t_decryptverify6_CPPFLAGS = $(cppflags_qt6)
t_disablekey6_SOURCES = t-disablekey.cpp $(support_src)
t_disablekey6_LDADD = $(ldadd_qt6)
t_disablekey6_CPPFLAGS = $(cppflags_qt6)
t_encrypt6_SOURCES = t-encrypt.cpp $(support_src)
t_encrypt6_LDADD = $(ldadd_qt6)
t_encrypt6_CPPFLAGS = $(cppflags_qt6)
t_import6_SOURCES = t-import.cpp $(support_src)
t_import6_LDADD = $(ldadd_qt6)
t_import6_CPPFLAGS = $(cppflags_qt6)
t_keylist6_SOURCES = t-keylist.cpp $(support_src)
t_keylist6_LDADD = $(ldadd_qt6)
t_keylist6_CPPFLAGS = $(cppflags_qt6)
t_keylocate6_SOURCES = t-keylocate.cpp $(support_src)
t_keylocate6_LDADD = $(ldadd_qt6)
t_keylocate6_CPPFLAGS = $(cppflags_qt6)
t_ownertrust6_SOURCES = t-ownertrust.cpp $(support_src)
t_ownertrust6_LDADD = $(ldadd_qt6)
t_ownertrust6_CPPFLAGS = $(cppflags_qt6)
t_remarks6_SOURCES = t-remarks.cpp $(support_src)
t_remarks6_LDADD = $(ldadd_qt6)
t_remarks6_CPPFLAGS = $(cppflags_qt6)
t_revokekey6_SOURCES = t-revokekey.cpp $(support_src)
t_revokekey6_LDADD = $(ldadd_qt6)
t_revokekey6_CPPFLAGS = $(cppflags_qt6)
t_setprimaryuserid6_SOURCES = t-setprimaryuserid.cpp $(support_src)
t_setprimaryuserid6_LDADD = $(ldadd_qt6)
t_setprimaryuserid6_CPPFLAGS = $(cppflags_qt6)
t_tofuinfo6_SOURCES = t-tofuinfo.cpp $(support_src)
t_tofuinfo6_LDADD = $(ldadd_qt6)
t_tofuinfo6_CPPFLAGS = $(cppflags_qt6)
t_trustsignatures6_SOURCES = t-trustsignatures.cpp $(support_src)
t_trustsignatures6_LDADD = $(ldadd_qt6)
t_trustsignatures6_CPPFLAGS = $(cppflags_qt6)
t_various6_SOURCES = t-various.cpp $(support_src)
t_various6_LDADD = $(ldadd_qt6)
t_various6_CPPFLAGS = $(cppflags_qt6)
t_verify6_SOURCES = t-verify.cpp $(support_src)
t_verify6_LDADD = $(ldadd_qt6)
t_verify6_CPPFLAGS = $(cppflags_qt6)
t_wkdlookup6_SOURCES = t-wkdlookup.cpp $(support_src)
t_wkdlookup6_LDADD = $(ldadd_qt6)
t_wkdlookup6_CPPFLAGS = $(cppflags_qt6)
# t_wkspublish6_SOURCES = t-wkspublish.cpp $(support_src)
# t_wkspublish6_LDADD = $(ldadd_qt6)
# t_wkspublish6_CPPFLAGS = $(cppflags_qt6)
run_decryptverifyarchivejob6_SOURCES = run-decryptverifyarchivejob.cpp
run_decryptverifyarchivejob6_LDADD = $(ldadd_qt6)
run_decryptverifyarchivejob6_CPPFLAGS = $(cppflags_qt6)
run_decryptverifyjob6_SOURCES = run-decryptverifyjob.cpp
run_decryptverifyjob6_LDADD = $(ldadd_qt6)
run_decryptverifyjob6_CPPFLAGS = $(cppflags_qt6)
run_encryptarchivejob6_SOURCES = run-encryptarchivejob.cpp
run_encryptarchivejob6_LDADD = $(ldadd_qt6)
run_encryptarchivejob6_CPPFLAGS = $(cppflags_qt6)
run_encryptjob6_SOURCES = run-encryptjob.cpp
run_encryptjob6_LDADD = $(ldadd_qt6)
run_encryptjob6_CPPFLAGS = $(cppflags_qt6)
run_exportjob6_SOURCES = run-exportjob.cpp
run_exportjob6_LDADD = $(ldadd_qt6)
run_exportjob6_CPPFLAGS = $(cppflags_qt6)
run_importjob6_SOURCES = run-importjob.cpp
run_importjob6_LDADD = $(ldadd_qt6)
run_importjob6_CPPFLAGS = $(cppflags_qt6)
run_keyformailboxjob6_SOURCES = run-keyformailboxjob.cpp
run_keyformailboxjob6_LDADD = $(ldadd_qt6)
run_keyformailboxjob6_CPPFLAGS = $(cppflags_qt6)
run_receivekeysjob6_SOURCES = run-receivekeysjob.cpp
run_receivekeysjob6_LDADD = $(ldadd_qt6)
run_receivekeysjob6_CPPFLAGS = $(cppflags_qt6)
run_refreshkeysjob6_SOURCES = run-refreshkeysjob.cpp
run_refreshkeysjob6_LDADD = $(ldadd_qt6)
run_refreshkeysjob6_CPPFLAGS = $(cppflags_qt6)
run_signarchivejob6_SOURCES = run-signarchivejob.cpp
run_signarchivejob6_LDADD = $(ldadd_qt6)
run_signarchivejob6_CPPFLAGS = $(cppflags_qt6)
run_signjob6_SOURCES = run-signjob.cpp
run_signjob6_LDADD = $(ldadd_qt6)
run_signjob6_CPPFLAGS = $(cppflags_qt6)
run_verifydetachedjob6_SOURCES = run-verifydetachedjob.cpp
run_verifydetachedjob6_LDADD = $(ldadd_qt6)
run_verifydetachedjob6_CPPFLAGS = $(cppflags_qt6)
run_verifyopaquejob6_SOURCES = run-verifyopaquejob.cpp
run_verifyopaquejob6_LDADD = $(ldadd_qt6)
run_verifyopaquejob6_CPPFLAGS = $(cppflags_qt6)
run_wkdrefreshjob6_SOURCES = run-wkdrefreshjob.cpp
run_wkdrefreshjob6_LDADD = $(ldadd_qt6)
run_wkdrefreshjob6_CPPFLAGS = $(cppflags_qt6)

# nodist_t_keylist6_SOURCES = $(moc6_files) $(moc6_forward_headers)
endif

BUILT_SOURCES = $(moc5_files) $(moc5_forward_headers) \
		$(moc6_files) $(moc6_forward_headers) \
		pubring-stamp

noinst_PROGRAMS = $(the_tests5) $(the_runners5) $(the_tests6) $(the_runners6)

CLEANFILES = secring.gpg pubring.gpg pubring.kbx trustdb.gpg dirmngr.conf \
	gpg-agent.conf pubring.kbx~ S.gpg-agent gpg.conf pubring.gpg~ \
	random_seed S.gpg-agent .gpg-v21-migrated pubring-stamp \
	$(moc5_files) $(moc5_forward_headers) \
	$(moc6_files) $(moc6_forward_headers) \
	gpg.conf tofu.db reader_0.status reader_1.status

clean-local:
	-test -z "$(moc5_dir)" || rm -rf $(moc5_dir)
	-test -z "$(moc6_dir)" || rm -rf $(moc6_dir)
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
	-$(TESTS_ENVIRONMENT) gpgconf --kill all
	touch pubring-stamp
