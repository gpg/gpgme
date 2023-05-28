# Makefile.am for the Python bindings.
# Copyright (C) 2016 g10 Code GmbH
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

EXTRA_DIST = \
	README \
	MANIFEST.in \
	gpgme.i \
	helpers.c helpers.h private.h

if RUN_GPG_TESTS
tests = tests
else
tests =
endif

SUBDIRS = . ${tests} examples doc src

.PHONY: prepare
prepare: copystamp

# For VPATH builds we need to copy some files because Python's
# distutils are not VPATH-aware.
copystamp:
	ln -sf "$(top_srcdir)/src/data.h" .
	ln -sf "$(top_builddir)/conf/config.h" .
	ln -sf "$(srcdir)/src" gpg
	touch $@

all-local: copystamp
	set -e ; for PYTHON in $(PYTHONS); do \
	  CPP="$(CPP)" \
	  CFLAGS="$(CFLAGS)" \
	  srcdir="$(srcdir)" \
	  top_builddir="$(top_builddir)" \
	    $$PYTHON setup.py build --verbose --build-base="$$(basename "$${PYTHON}")-gpg" ; \
	done

python$(PYTHON_VERSION)-gpg/dist/gpg-$(VERSION).tar.gz.asc: copystamp
	$(MKDIR_P) python$(PYTHON_VERSION)-gpg-dist
	CPP="$(CPP)" \
	CFLAGS="$(CFLAGS)" \
	srcdir="$(srcdir)" \
	top_builddir="$(top_builddir)" \
	  $(PYTHON) setup.py sdist --verbose --dist-dir=python$(PYTHON_VERSION)-gpg-dist \
		--manifest=python$(PYTHON_VERSION)-gpg-dist/MANIFEST
	gpgbin=gpgconf --list-components | grep OpenPGP | sed -e 's/gpg:OpenPGP://g'
	$(gpgbin) --detach-sign --armor python$(PYTHON_VERSION)-gpg-dist/gpg-$(VERSION).tar.gz

.PHONY: sdist
sdist:	python$(PYTHON_VERSION)-gpg/dist/gpg-$(VERSION).tar.gz.asc

.PHONY: upload
upload: python$(PYTHON_VERSION)-gpg-dist/gpg-$(VERSION).tar.gz \
        python$(PYTHON_VERSION)-gpg-dist/gpg-$(VERSION).tar.gz.asc
	twine upload $^

CLEANFILES = copystamp \
	config.h \
	data.h \
	gpg

# Remove the rest.
#
# 'make distclean' clears the write bit, breaking rm -rf.  Fix the
# permissions.
clean-local:
	rm -rf -- build
	for PYTHON in $(PYTHONS); do \
	  find "$$(basename "$${PYTHON}")-gpg" -type d ! -perm -200 -exec chmod u+w {} ';' ; \
	  rm -rf -- "$$(basename "$${PYTHON}")-gpg" ; \
	done

install-exec-local:
	set -e ; for PYTHON in $(PYTHONS); do \
	  CPP="$(CPP)" \
	  CFLAGS="$(CFLAGS)" \
	  srcdir="$(srcdir)" \
	  top_builddir="$(top_builddir)" \
	  $$PYTHON setup.py \
	  build \
	  --build-base="$$(basename "$${PYTHON}")-gpg" \
	  install \
	  --prefix "$(DESTDIR)$(prefix)" \
	  --verbose ; \
	done

uninstall-local:
	set -x; GV=$$(echo $(VERSION) | tr - _); for PYTHON in $(PYTHONS); do \
	  PLATLIB="$(prefix)/$$("$${PYTHON}" -c 'import sysconfig, os; print(os.path.relpath(sysconfig.get_path("platlib", scheme="posix_prefix"), sysconfig.get_config_var("prefix")))')" ; \
	  rm -rf -- "$(DESTDIR)$${PLATLIB}/gpg" \
		"$(DESTDIR)$${PLATLIB}"/gpg-$$GV-py*.egg-info ; \
	done
