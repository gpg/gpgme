# Makefile.am for the tests of the Python bindings.
# Copyright (C) 2016 g10 Code GmbH
#
# This file is part of GPGME.
#
# GPGME is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# GPGME is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General
# Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, see <http://www.gnu.org/licenses/>.

GPG = gpg
GPG_AGENT = gpg-agent
export GNUPGHOME := $(abs_builddir)
export GPG_AGENT_INFO :=

test_srcdir = $(top_srcdir)/tests/gpg

TESTS_ENVIRONMENT = GNUPGHOME=$(abs_builddir) \
	LC_ALL=C GPG_AGENT_INFO= \
	top_srcdir=$(top_srcdir) \
	LD_LIBRARY_PATH="../../../src/.libs" \
	PYTHONPATH=`echo $(abs_builddir)/../build/lib.*`

py_tests = t-wrapper.py \
	t-callbacks.py \
	t-data.py \
	t-encrypt.py \
	t-encrypt-sym.py \
	t-encrypt-sign.py \
	t-sign.py \
	t-signers.py \
	t-decrypt.py \
	t-export.py \
	t-edit.py

TESTS = $(top_srcdir)/tests/gpg/initial.test \
	$(py_tests) \
	$(top_srcdir)/tests/gpg/final.test

CLEANFILES = secring.gpg pubring.gpg pubring.kbx trustdb.gpg dirmngr.conf \
	gpg-agent.conf pubring.kbx~ gpg.conf pubring.gpg~ \
	random_seed .gpg-v21-migrated pubring-stamp

private_keys = \
        $(test_srcdir)/13CD0F3BDF24BE53FE192D62F18737256FF6E4FD \
        $(test_srcdir)/76F7E2B35832976B50A27A282D9B87E44577EB66 \
        $(test_srcdir)/A0747D5F9425E6664F4FFBEED20FBCA79FDED2BD \
        $(test_srcdir)/13CBE3758AFE42B5E5E2AE4CED27AFA455E3F87F \
        $(test_srcdir)/7A030357C0F253A5BBCD282FFC4E521B37558F5C

clean-local:
	-$(top_srcdir)/tests/start-stop-agent --stop
	-rm -fR -- private-keys-v1.d openpgp-revocs.d S.gpg-agent sshcontrol

check-local: ./gpg.conf ./gpg-agent.conf ./pubring-stamp \
           ./private-keys-v1.d/gpg-sample.stamp

# To guarantee that check-local is run before any tests we
# add this dependency:
$(top_srcdir)/tests/gpg/initial.test: check-local

./private-keys-v1.d/gpg-sample.stamp: $(private_keys)
	test -d ./private-keys-v1.d || mkdir ./private-keys-v1.d
	for k in $(private_keys); do \
          cp $$k private-keys-v1.d/`basename $$k`.key; \
        done
	echo x > ./private-keys-v1.d/gpg-sample.stamp

./pubring-stamp: $(test_srcdir)/pubdemo.asc
	$(GPG) --no-permission-warning \
               --import $(test_srcdir)/pubdemo.asc
	-$(GPG) --no-permission-warning \
		--import $(test_srcdir)/secdemo.asc
	touch ./pubring-stamp

./gpg.conf:
# This is required for t-sig-notations.
	echo no-force-v3-sigs > ./gpg.conf

./gpg-agent.conf:
# This is required for gpg2, which does not support command fd.
	echo pinentry-program $(abs_top_srcdir)/tests/gpg/pinentry > ./gpg-agent.conf
