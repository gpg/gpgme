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
# License along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

## Process this file with automake to produce Makefile.in

GPGSM = gpgsm

TESTS_ENVIRONMENT = GNUPGHOME=$(abs_builddir) LC_ALL=C GPG_AGENT_INFO= \
                    top_srcdir=$(top_srcdir)

noinst_HEADERS = t-support.h

c_tests = t-import t-keylist t-encrypt t-verify t-decrypt t-sign t-export


TESTS = initial.test $(c_tests) final.test

EXTRA_DIST = cert_dfn_pca01.der cert_dfn_pca15.der cert_g10code_test1.der \
	$(key_id) initial.test final.test

AM_CPPFLAGS = -I$(top_builddir)/src @GPG_ERROR_CFLAGS@
AM_LDFLAGS = -no-install
LDADD = ../../src/libgpgme.la

# We don't run t-genkey in the test suite, because it takes too long
# and needs a working pinentry.
noinst_PROGRAMS = $(c_tests) t-genkey cms-keylist cms-decrypt

key_id = 32100C27173EF6E9C4E9A25D3D69F86D37A4F939

CLEANFILES = pubring.kbx pubring.kbx~ gpgsm.conf trustlist.txt \
	random_seed S.gpg-agent

clean-local:
	-$(top_srcdir)/tests/start-stop-agent --stop
	-rm -fR private-keys-v1.d

check-local: ./pubring.kbx ./gpgsm.conf \
             ./private-keys-v1.d/$(key_id).key ./trustlist.txt

# To guarantee that check-local is run before any tests we add this
# dependency:
initial.test : check-local

export GNUPGHOME := $(abs_builddir)

export GPG_AGENT_INFO :=

./pubring.kbx: $(srcdir)/cert_g10code_test1.der
	$(GPGSM) --import $(srcdir)/cert_g10code_test1.der

./gpgsm.conf:
	echo disable-crl-checks > ./gpgsm.conf
	echo faked-system-time 1008241200 >> ./gpgsm.conf

./private-keys-v1.d/$(key_id).key: $(srcdir)/$(key_id)
	test -d ./private-keys-v1.d || mkdir ./private-keys-v1.d
	cp $(srcdir)/$(key_id) private-keys-v1.d/$(key_id).key

./trustlist.txt:
	echo $(key_id) > ./trustlist.txt
	echo >> ./trustlist.txt
	echo "# CN=test cert 1,OU=Aegypten Project,O=g10 Code GmbH,L=Düsseldorf,C=DE" >> ./trustlist.txt
	echo "3CF405464F66ED4A7DF45BBDD1E4282E33BDB76E S" >> ./trustlist.txt

