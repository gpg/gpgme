# Copyright (C) 2000 Werner Koch (dd9jn)
# Copyright (C) 2001 g10 Code GmbH
# 
# This file is part of GPGME.
# 
# GPGME is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# GPGME is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

## Process this file with automake to produce Makefile.in

GPGSM = @GPGSM@

TESTS_ENVIRONMENT = GNUPGHOME=.

TESTS = t-import t-keylist t-encrypt t-verify t-decrypt t-sign

EXTRA_DIST = cert_dfn_pca01.der cert_dfn_pca15.der cert_g10code_test1.der $(key_id)

INCLUDES = -I$(top_srcdir)/gpgme

LDADD = ../../gpgme/libgpgme.la

noinst_PROGRAMS = $(TESTS)

key_id := 32100C27173EF6E9C4E9A25D3D69F86D37A4F939

all-local: ./pubring.kbx ./gpg-agent.conf ./gpgsm.conf ./private-keys-v1.d/$(key_id).key ./trustlist.txt

./pubring.kbx: $(srcdir)/cert_g10code_test1.der
	$(GPGSM) --homedir . --import $(srcdir)/cert_g10code_test1.der

./gpg-agent.conf:
	echo batch > ./gpg-agent.conf

./gpgsm.conf:
	echo disable-crl-checks > ./gpgsm.conf

./private-keys-v1.d/$(key_id).key: $(srcdir)/$(key_id)
	test -d ./private-keys-v1.d || mkdir ./private-keys-v1.d
	cp $(srcdir)/$(key_id) private-keys-v1.d/$(key_id).key

./trustlist.txt:
	echo $(key_id) > ./trustlist.txt
