# Copyright (C) 2018 Bundesamt für Sicherheit in der Informationstechnik
#                    Software engineering by Intevation GmbH
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

GPGME_JSON=$(abs_builddir)/../../src/gpgme-json
GPG = gpg

GNUPGHOME=$(abs_builddir)
TESTS_ENVIRONMENT = GNUPGHOME=$(GNUPGHOME) LC_ALL=C GPG_AGENT_INFO= \
                    top_srcdir=$(top_srcdir) gpgme_json=$(GPGME_JSON)

c_tests = t-json

TESTS = initial.test $(c_tests) final.test

CLEANFILES = secring.gpg pubring.gpg pubring.kbx trustdb.gpg dirmngr.conf \
	gpg-agent.conf pubring.kbx~ S.gpg-agent gpg.conf pubring.gpg~ \
	random_seed S.gpg-agent .gpg-v21-migrated pubring-stamp \
	gpg-sample.stamp tofu.db *.conf.gpgconf.bak

private_keys = \
        $(top_srcdir)/tests/gpg/13CD0F3BDF24BE53FE192D62F18737256FF6E4FD \
        $(top_srcdir)/tests/gpg/76F7E2B35832976B50A27A282D9B87E44577EB66 \
        $(top_srcdir)/tests/gpg/A0747D5F9425E6664F4FFBEED20FBCA79FDED2BD \
        $(top_srcdir)/tests/gpg/13CBE3758AFE42B5E5E2AE4CED27AFA455E3F87F \
        $(top_srcdir)/tests/gpg/7A030357C0F253A5BBCD282FFC4E521B37558F5C


EXTRA_DIST = initial.test final.test \
		t-chunking.in.json t-chunking.out.json \
		t-config.in.json t-config-opt.in.json \
		t-config-opt.out.json t-config.out.json \
		t-createkey.in.json t-createkey.out.json \
		t-decrypt.in.json t-decrypt.out.json \
		t-decrypt-verify.in.json t-decrypt-verify.out.json \
		t-delete.in.json t-delete.out.json \
		t-encrypt.in.json t-encrypt.out.json \
		t-encrypt-sign.in.json t-encrypt-sign.out.json \
		t-export.in.json t-export.out.json \
		t-export-secret-info.in.json t-export-secret-info.out.json \
		t-import.in.json t-import.out.json \
		t-keylist.in.json t-keylist.out.json \
		t-keylist-secret.in.json t-keylist-secret.out.json \
		t-sign.in.json t-sign.out.json \
		t-sig-notations.in.json t-sig-notations.out.json \
		t-verify.in.json t-verify.out.json \
		t-version.in.json t-version.out.json

BUILT_SOURCES = gpg.conf gpg-agent.conf pubring-stamp \
           gpg-sample.stamp
t_json_SOURCES = t-json.c
AM_LDFLAGS = -no-install
LDADD = ../../src/libgpgme.la @LDADD_FOR_TESTS_KLUDGE@
t_json_LDADD = ../../src/cJSON.o -lm ../../src/libgpgme.la @GPG_ERROR_LIBS@ \
	       @LDADD_FOR_TESTS_KLUDGE@

AM_CPPFLAGS = -I$(top_builddir)/src @GPG_ERROR_CFLAGS@

noinst_PROGRAMS = $(c_tests)

clean-local:
	-$(TESTS_ENVIRONMENT) $(top_srcdir)/tests/start-stop-agent --stop
	-rm -fR private-keys-v1.d
	-rm -fR openpgp-revocs.d

gpg-sample.stamp: $(private_keys)
	-$(TESTS_ENVIRONMENT) gpgconf --kill all
	$(MKDIR_P) ./private-keys-v1.d
	for k in $(private_keys); do \
          cp $$k private-keys-v1.d/$$(basename $$k).key; \
        done
	echo x > ./gpg-sample.stamp

pubring-stamp: $(top_srcdir)/tests/gpg/pubdemo.asc \
	       $(top_srcdir)/tests/json/key-with-revokers.asc \
	       gpg-sample.stamp
	$(TESTS_ENVIRONMENT) $(GPG) --batch --no-permission-warning \
               --import $(top_srcdir)/tests/gpg/pubdemo.asc
	$(TESTS_ENVIRONMENT) $(GPG) --batch --no-permission-warning \
		--import $(top_srcdir)/tests/json/key-with-revokers.asc
	-$(TESTS_ENVIRONMENT) $(GPG) --batch --no-permission-warning \
		--import $(top_srcdir)/tests/gpg/secdemo.asc
	-$(TESTS_ENVIRONMENT) gpgconf --kill all
	echo x > ./pubring-stamp

gpg.conf:
# This is required for t-sig-notations.
	echo no-force-v3-sigs > ./gpg.conf

gpg-agent.conf:
# This is required for gpg2, which does not support command fd for the
# passphrase.  disable-scdaemon is required so that we don't try using
# a key from a smartcard reader (error might be: Unusable secret key)
	echo pinentry-program $(abs_srcdir)/../gpg/pinentry > ./gpg-agent.conf
	echo disable-scdaemon >> ./gpg-agent.conf


# end-of-file
