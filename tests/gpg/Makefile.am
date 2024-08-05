# Copyright (C) 2000 Werner Koch (dd9jn)
# Copyright (C) 2001, 2004, 2005, 2009 g10 Code GmbH
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

GPG = gpg
GPG_AGENT = gpg-agent

GNUPGHOME=$(abs_builddir)
TESTS_ENVIRONMENT = GNUPGHOME=$(GNUPGHOME) LC_ALL=C GPG_AGENT_INFO= \
                    top_srcdir=$(top_srcdir)

# The keylist tests must come after the import and the edit test.
noinst_HEADERS = t-support.h

if HAVE_W32_SYSTEM
tests_unix =
else
tests_unix = t-eventloop t-thread1 t-thread-keylist t-thread-keylist-verify
endif

c_tests = \
        t-encrypt t-encrypt-sym t-encrypt-sign t-sign t-signers		\
	t-decrypt t-verify t-decrypt-verify t-sig-notation t-export	\
	t-import t-edit t-keylist t-keylist-sig t-keylist-secret-sig t-wait \
	t-encrypt-large t-file-name t-gpgconf t-encrypt-mixed t-edit-sign \
	t-setownertrust							\
	$(tests_unix)

TESTS = initial.test $(c_tests) final.test

CLEANFILES = secring.gpg pubring.gpg pubring.kbx trustdb.gpg dirmngr.conf \
	gpg-agent.conf pubring.kbx~ S.gpg-agent gpg.conf pubring.gpg~ \
	random_seed S.gpg-agent .gpg-v21-migrated pubring-stamp \
	gpg-sample.stamp tofu.db *.conf.gpgconf.bak

private_keys = \
        13CD0F3BDF24BE53FE192D62F18737256FF6E4FD \
        76F7E2B35832976B50A27A282D9B87E44577EB66 \
        A0747D5F9425E6664F4FFBEED20FBCA79FDED2BD \
        13CBE3758AFE42B5E5E2AE4CED27AFA455E3F87F \
        7A030357C0F253A5BBCD282FFC4E521B37558F5C


EXTRA_DIST = initial.test final.test \
        pubdemo.asc secdemo.asc cipher-1.asc cipher-2.asc \
	cipher-3.asc cipher-no-sig.asc \
	geheim.txt pubkey-1.asc seckey-1.asc pinentry $(private_keys) \
	gpg.conf.in ownertrust.txt

BUILT_SOURCES = gpg.conf gpg-agent.conf pubring-stamp \
           gpg-sample.stamp
AM_CPPFLAGS = -I$(top_builddir)/src @GPG_ERROR_CFLAGS@
AM_LDFLAGS = -no-install
LDADD = ../../src/libgpgme.la @GPG_ERROR_LIBS@ @LDADD_FOR_TESTS_KLUDGE@

WITH_THREAD_CPPFLAGS =  -I$(top_builddir)/src @GPG_ERROR_MT_CFLAGS@
WITH_THREAD_LDADD = ../../src/libgpgme.la \
	@GPG_ERROR_MT_LIBS@ @LDADD_FOR_TESTS_KLUDGE@
t_thread1_CPPFLAGS = $(WITH_THREAD_CPPFLAGS)
t_thread1_LDADD = $(WITH_THREAD_LDADD)
t_thread_keylist_CPPFLAGS = $(WITH_THREAD_CPPFLAGS)
t_thread_keylist_LDADD = $(WITH_THREAD_LDADD)
t_thread_keylist_verify_CPPFLAGS = $(WITH_THREAD_CPPFLAGS)
t_thread_keylist_verify_LDADD = $(WITH_THREAD_LDADD)
t_cancel_CPPFLAGS = $(WITH_THREAD_CPPFLAGS)
t_cancel_LDADD = $(WITH_THREAD_LDADD)

# We don't run t-genkey and t-cancel in the test suite, because it
# takes too long
tests_skipped = t-genkey
if !HAVE_W32_SYSTEM
tests_skipped += t-cancel
endif

noinst_PROGRAMS = $(c_tests) $(tests_skipped)


clean-local:
	-$(TESTS_ENVIRONMENT) $(top_srcdir)/tests/start-stop-agent --stop
	-rm -fR private-keys-v1.d

gpg-sample.stamp: $(srcdir)/$(private_keys)
	-$(TESTS_ENVIRONMENT) gpgconf --kill all
	$(MKDIR_P) ./private-keys-v1.d
	for k in $(private_keys); do \
	  cp $(srcdir)/$$k private-keys-v1.d/$$k.key; \
	done
	echo x > ./gpg-sample.stamp

pubring-stamp: $(srcdir)/pubdemo.asc gpg-sample.stamp
	$(TESTS_ENVIRONMENT) $(GPG) --batch --no-permission-warning \
		--import $(srcdir)/pubdemo.asc
	-$(TESTS_ENVIRONMENT) $(GPG) --batch --no-permission-warning \
		--import $(srcdir)/secdemo.asc
	-$(TESTS_ENVIRONMENT) $(GPG) --batch --no-permission-warning \
		--import-ownertrust $(srcdir)/ownertrust.txt
	-$(TESTS_ENVIRONMENT) gpgconf --kill all
	echo x > ./pubring-stamp

gpg.conf: $(srcdir)/gpg.conf.in
	cp $(srcdir)/gpg.conf.in gpg.conf

gpg-agent.conf:
# This is required for gpg2, which does not support command fd for the
# passphrase.  disable-scdaemon is required so that we don't try using
# a key from a smartcard reader (error might be: Unusable secret key)
	echo pinentry-program $(abs_srcdir)/pinentry > ./gpg-agent.conf
	echo disable-scdaemon >> ./gpg-agent.conf


# end-of-file
