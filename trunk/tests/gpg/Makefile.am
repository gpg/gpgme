# Copyright (C) 2000 Werner Koch (dd9jn)
# Copyright (C) 2001, 2004, 2005 g10 Code GmbH
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

GPG = @GPG@

TESTS_ENVIRONMENT = GNUPGHOME=. GPG_AGENT_INFO=

# The keylist tests must come after the import and the edit test.
noinst_HEADERS = t-support.h
TESTS = t-encrypt t-encrypt-sym t-encrypt-sign t-sign t-signers	\
	t-decrypt t-verify t-decrypt-verify t-sig-notation \
	t-export t-import t-trustlist t-eventloop t-edit \
	t-keylist t-keylist-sig t-thread1 t-wait t-encrypt-large \
	t-file-name

CLEANFILES = secring.gpg pubring.gpg trustdb.gpg
DISTCLEANFILES = pubring.gpg~ random_seed

EXTRA_DIST = mkdemodirs pubdemo.asc secdemo.asc cipher-1.asc cipher-2.asc \
	geheim.txt pubkey-1.asc seckey-1.asc gpg.conf

INCLUDES = -I$(top_srcdir)/gpgme

AM_CPPFLAGS = @GPG_ERROR_CFLAGS@
LDADD = ../../gpgme/libgpgme.la
t_thread1_LDADD = ../../gpgme/libgpgme-pthread.la

# We don't run t-genkey in the test suite, because it takes too long
noinst_PROGRAMS = $(TESTS) t-genkey

clean-local:
	$(srcdir)/mkdemodirs --clean

all-local: ./pubring.gpg

./pubring.gpg: $(srcdir)/pubdemo.asc ./Alpha/Secret.gpg 
	$(GPG) --homedir . --import $(srcdir)/pubdemo.asc
	$(GPG) --homedir . --allow-secret-key-import --import Alpha/Secret.gpg Zulu/Secret.gpg

./Alpha/Secret.gpg: secdemo.asc 
	srcdir=$(srcdir) $(srcdir)/mkdemodirs 
