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
# License along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

## Process this file with automake to produce Makefile.in

GPG = gpg
GPG_AGENT = gpg-agent

TESTS_ENVIRONMENT = GNUPGHOME=$(abs_builddir) LC_ALL=C GPG_AGENT_INFO= \
                    top_srcdir=$(top_srcdir)

# The keylist tests must come after the import and the edit test.
noinst_HEADERS = t-support.h

if HAVE_W32_SYSTEM
tests_unix =
else
tests_unix = t-eventloop t-thread1
endif

c_tests = \
        t-encrypt t-encrypt-sym t-encrypt-sign t-sign t-signers		\
	t-decrypt t-verify t-decrypt-verify t-sig-notation t-export	\
	t-import t-trustlist t-edit t-keylist t-keylist-sig t-wait	\
	t-encrypt-large t-file-name t-gpgconf t-encrypt-mixed $(tests_unix)

TESTS = initial.test $(c_tests) final.test

CLEANFILES = secring.gpg pubring.gpg pubring.kbx trustdb.gpg dirmngr.conf \
	gpg-agent.conf pubring.kbx~ S.gpg-agent gpg.conf pubring.gpg~ \
	random_seed S.gpg-agent .gpg-v21-migrated pubring-stamp

private_keys = \
        13CD0F3BDF24BE53FE192D62F18737256FF6E4FD \
        76F7E2B35832976B50A27A282D9B87E44577EB66 \
        A0747D5F9425E6664F4FFBEED20FBCA79FDED2BD \
        13CBE3758AFE42B5E5E2AE4CED27AFA455E3F87F \
        7A030357C0F253A5BBCD282FFC4E521B37558F5C


EXTRA_DIST = initial.test final.test \
        pubdemo.asc secdemo.asc cipher-1.asc cipher-2.asc \
	geheim.txt pubkey-1.asc seckey-1.asc pinentry $(private_keys)

AM_CPPFLAGS = -I$(top_builddir)/src @GPG_ERROR_CFLAGS@
AM_LDFLAGS = -no-install
LDADD = ../../src/libgpgme.la
t_thread1_LDADD = ../../src/libgpgme-pthread.la -lpthread

# We don't run t-genkey in the test suite, because it takes too long
noinst_PROGRAMS = $(c_tests) t-genkey

clean-local:
	-$(top_srcdir)/tests/start-stop-agent --stop
	-rm -fR private-keys-v1.d

check-local: ./gpg.conf ./gpg-agent.conf ./pubring-stamp \
           ./private-keys-v1.d/gpg-sample.stamp

# To guarantee that check-local is run before any tests we
# add this dependency:
initial.test : check-local

export GNUPGHOME := $(abs_builddir)

export GPG_AGENT_INFO :=

./private-keys-v1.d/gpg-sample.stamp: $(srcdir)/$(private_keys)
	test -d ./private-keys-v1.d || mkdir ./private-keys-v1.d
	for k in $(private_keys); do \
          cp $(srcdir)/$$k private-keys-v1.d/$$k.key; \
        done
	echo x > ./private-keys-v1.d/gpg-sample.stamp

./pubring-stamp: $(srcdir)/pubdemo.asc
	$(GPG) --batch --no-permission-warning \
               --import $(srcdir)/pubdemo.asc
	-$(GPG) --batch --no-permission-warning \
		--import $(srcdir)/secdemo.asc
	echo x > ./pubring-stamp

./gpg.conf:
# This is required for t-sig-notations.
	echo no-force-v3-sigs > ./gpg.conf

./gpg-agent.conf:
# This is required for gpg2, which does not support command fd.
	echo pinentry-program $(abs_srcdir)/pinentry > ./gpg-agent.conf
