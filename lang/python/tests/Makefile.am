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
# License along with this program; if not, see <https://www.gnu.org/licenses/>.

GPG = gpg
GPG_AGENT = gpg-agent

test_srcdir = $(top_srcdir)/tests/gpg

GNUPGHOME=$(abs_builddir)
TESTS_ENVIRONMENT = GNUPGHOME=$(GNUPGHOME) \
	LC_ALL=C GPG_AGENT_INFO= \
	top_srcdir=$(top_srcdir) \
	srcdir=$(srcdir) \
	LD_LIBRARY_PATH="../../../src/.libs:$(LD_LIBRARY_PATH)"

py_tests ?= t-wrapper.py \
	t-callbacks.py \
	t-data.py \
	t-encrypt.py \
	t-encrypt-sym.py \
	t-encrypt-sign.py \
	t-sign.py \
	t-signers.py \
	t-decrypt.py \
	t-verify.py \
	t-decrypt-verify.py \
	t-sig-notation.py \
	t-export.py \
	t-import.py \
	t-edit.py \
	t-keylist.py \
	t-keylist-from-data.py \
	t-wait.py \
	t-encrypt-large.py \
	t-file-name.py \
	t-idiomatic.py \
	t-protocol-assuan.py \
	t-quick-key-creation.py \
	t-quick-subkey-creation.py \
	t-quick-key-manipulation.py \
	t-quick-key-signing.py

XTESTS = initial.py $(py_tests) final.py
EXTRA_DIST = support.py $(XTESTS) encrypt-only.asc sign-only.asc \
             run-tests.py

# XXX: Currently, one cannot override automake's 'check' target.  As a
# workaround, we avoid defining 'TESTS', thus automake will not emit
# the 'check' target.  For extra robustness, we merely define a
# dependency on 'xcheck', so this hack should also work even if
# automake would emit the 'check' target, as adding dependencies to
# targets is okay.
check: xcheck

.PHONY: xcheck

xcheck:	all
	$(TESTS_ENVIRONMENT) $(PYTHON) $(srcdir)/run-tests.py \
	  --interpreters="$(PYTHONS)" --srcdir=$(srcdir) $(TESTFLAGS) \
	  $(XTESTS)

CLEANFILES = secring.gpg pubring.gpg pubring.kbx trustdb.gpg dirmngr.conf \
	gpg-agent.conf pubring.kbx~ gpg.conf pubring.gpg~ \
	random_seed .gpg-v21-migrated tofu.db \
        pubring-stamp gpg-sample.stamp

private_keys = \
        $(test_srcdir)/13CD0F3BDF24BE53FE192D62F18737256FF6E4FD \
        $(test_srcdir)/76F7E2B35832976B50A27A282D9B87E44577EB66 \
        $(test_srcdir)/A0747D5F9425E6664F4FFBEED20FBCA79FDED2BD \
        $(test_srcdir)/13CBE3758AFE42B5E5E2AE4CED27AFA455E3F87F \
        $(test_srcdir)/7A030357C0F253A5BBCD282FFC4E521B37558F5C

clean-local:
	-$(TESTS_ENVIRONMENT) $(top_srcdir)/tests/start-stop-agent --stop
	-rm -fR -- private-keys-v1.d openpgp-revocs.d S.gpg-agent sshcontrol


BUILT_SOURCES = gpg.conf gpg-agent.conf pubring-stamp \
           gpg-sample.stamp

gpg-sample.stamp: $(private_keys)
	-$(TESTS_ENVIRONMENT) gpgconf --kill all
	$(MKDIR_P) ./private-keys-v1.d
	for k in $(private_keys); do \
          cp $$k private-keys-v1.d/$${k#$(test_srcdir)/}.key; \
        done
	echo x > ./gpg-sample.stamp

pubring-stamp: $(test_srcdir)/pubdemo.asc gpg-sample.stamp
	$(TESTS_ENVIRONMENT) $(GPG) --batch --no-permission-warning \
               --import $(test_srcdir)/pubdemo.asc
	-$(TESTS_ENVIRONMENT) $(GPG) --batch --no-permission-warning \
		--import $(test_srcdir)/secdemo.asc
	-$(TESTS_ENVIRONMENT) gpgconf --kill all
	echo x > ./pubring-stamp

gpg.conf:
# This is required for t-sig-notations.
	echo no-force-v3-sigs > ./gpg.conf
	echo default-key A0FF4590BB6122EDEF6E3C542D727CC768697734 >> ./gpg.conf

gpg-agent.conf:
# This is required for gpg2, which does not support command fd.
	echo pinentry-program $(abs_top_srcdir)/tests/gpg/pinentry >$@
	echo disable-scdaemon >> $@


# end-of-file
