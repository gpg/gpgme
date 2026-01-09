# Copyright (C) 2000 Werner Koch (dd9jn)
# Copyright (C) 2001 g10 Code GmbH
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

GPGSM = gpgsm
GPG_AGENT = gpg-agent

GNUPGHOME=$(abs_builddir)
TESTS_ENVIRONMENT = GNUPGHOME=$(GNUPGHOME) LC_ALL=C GPG_AGENT_INFO= \
                    top_srcdir=$(top_srcdir)

noinst_HEADERS = t-support.h

c_tests = t-import t-keylist t-encrypt t-verify t-decrypt t-sign t-export


TESTS = initial.test $(c_tests) final.test

EXTRA_DIST = cert_dfn_pca01.der cert_dfn_pca15.der cert_g10code_test1.der \
	$(key_id) initial.test final.test

AM_CPPFLAGS = -I$(top_builddir)/src @GPG_ERROR_CFLAGS@
AM_LDFLAGS = -no-install
LDADD = ../../src/libgpgme.la @LDADD_FOR_TESTS_KLUDGE@

# We don't run t-genkey in the test suite, because it takes too long
# and needs a working pinentry.
noinst_PROGRAMS = $(c_tests) t-genkey cms-keylist cms-decrypt

key_id = 32100C27173EF6E9C4E9A25D3D69F86D37A4F939

CLEANFILES = pubring-stamp pubring.kbx pubring.kbx~ gpgsm.conf trustlist.txt \
	random_seed S.gpg-agent gpg-sample.stamp

clean-local:
	-$(TESTS_ENVIRONMENT) $(top_srcdir)/tests/start-stop-agent --stop
	-rm -fR private-keys-v1.d

BUILT_SOURCES = gpgsm.conf trustlist.txt pubring-stamp \
           gpg-sample.stamp

pubring-stamp: $(srcdir)/cert_g10code_test1.der gpg-sample.stamp
	$(TESTS_ENVIRONMENT) $(GPGSM) --import $(srcdir)/cert_g10code_test1.der
	touch pubring-stamp

gpgsm.conf:
	echo disable-crl-checks > ./gpgsm.conf
	echo faked-system-time 1008241200 >> ./gpgsm.conf

gpg-sample.stamp: $(srcdir)/$(key_id)
	-$(TESTS_ENVIRONMENT) gpgconf --kill all
	$(MKDIR_P) ./private-keys-v1.d
	cp $(srcdir)/$(key_id) private-keys-v1.d/$(key_id).key
	echo x > ./gpg-sample.stamp

trustlist.txt:
	echo $(key_id) > ./trustlist.txt
	echo >> ./trustlist.txt
	echo "# CN=test cert 1,OU=Aegypten Project,O=g10 Code GmbH,L=Düsseldorf,C=DE" >> ./trustlist.txt
	echo "3CF405464F66ED4A7DF45BBDD1E4282E33BDB76E S" >> ./trustlist.txt

