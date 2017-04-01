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
# License along with this program; if not, see <http://www.gnu.org/licenses/>.

EXTRA_DIST = \
	README \
	MANIFEST.in \
	gpgme.i \
	helpers.c helpers.h private.h \
	gpgme-h-clean.py \
	examples \
	gpg

SUBDIRS = . tests

.PHONY: prepare
prepare: copystamp

# For VPATH builds we need to copy some files because Python's
# distutils are not VPATH-aware.
copystamp:
	ln -sf "$(abs_top_srcdir)/src/data.h" .
	ln -sf "$(abs_top_builddir)/config.h" .
	touch $@

all-local: copystamp
	set -e ; set $(PYTHONS); for VERSION in $(PYTHON_VERSIONS); do \
	  PYTHON="$$1" ; shift ; \
	  CFLAGS="$(CFLAGS)" \
	  abs_top_builddir="$(abs_top_builddir)" \
	    $$PYTHON setup.py build --verbose --build-base=python$${VERSION}-gpg ; \
	done

python$(PYTHON_VERSION)-gpg/dist/gpg-$(VERSION).tar.gz.asc: copystamp
	$(MKDIR_P) python$(PYTHON_VERSION)-gpg-dist
	CFLAGS="$(CFLAGS)" \
	abs_top_builddir="$(abs_top_builddir)" \
	  $(PYTHON) setup.py sdist --verbose --dist-dir=python$(PYTHON_VERSION)-gpg-dist \
		--manifest=python$(PYTHON_VERSION)-gpg-dist/MANIFEST
	gpg2 --detach-sign --armor python$(PYTHON_VERSION)-gpg-dist/gpg-$(VERSION).tar.gz

.PHONY: sdist
sdist:	python$(PYTHON_VERSION)-gpg/dist/gpg-$(VERSION).tar.gz.asc

.PHONY: upload
upload: python$(PYTHON_VERSION)-gpg-dist/gpg-$(VERSION).tar.gz \
        python$(PYTHON_VERSION)-gpg-dist/gpg-$(VERSION).tar.gz.asc
	twine upload $^

CLEANFILES = copystamp \
	config.h \
	data.h \
	files.txt \
	install_files.txt

# Remove the rest.
#
# 'make distclean' clears the write bit, breaking rm -rf.  Fix the
# permissions.
clean-local:
	rm -rf -- build
	for VERSION in $(PYTHON_VERSIONS); do \
	  find python$${VERSION}-gpg -type d ! -perm -200 -exec chmod u+w {} ';' ; \
	  rm -rf -- python$${VERSION}-gpg ; \
	done

install-exec-local:
	set -e ; set $(PYTHONS); for VERSION in $(PYTHON_VERSIONS); do \
	  PYTHON="$$1" ; shift ; \
	  abs_top_builddir="$(abs_top_builddir)" \
	  $$PYTHON setup.py \
	  build \
	  --build-base=python$${VERSION}-gpg \
	  install \
	  --prefix "$(DESTDIR)$(prefix)" \
	  --record files.txt \
	  --verbose ; \
	  cat files.txt >> install_files.txt ; \
	  rm files.txt ; \
	done
	$(MKDIR_P) "$(DESTDIR)$(pythondir)/gpg"
	mv install_files.txt "$(DESTDIR)$(pythondir)/gpg"

uninstall-local:
	xargs < "$(DESTDIR)$(pythondir)/gpg/install_files.txt" -- rm -rf --
	rm -rf -- "$(DESTDIR)$(pythondir)/gpg"
