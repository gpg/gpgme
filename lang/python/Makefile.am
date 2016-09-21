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
	pyme

SUBDIRS = . tests

COPY_FILES = \
	$(srcdir)/gpgme.i \
	$(srcdir)/README \
	$(srcdir)/MANIFEST.in \
	$(srcdir)/gpgme-h-clean.py \
	$(srcdir)/examples \
	$(srcdir)/helpers.c $(srcdir)/helpers.h $(srcdir)/private.h

COPY_FILES_PYME = \
	$(srcdir)/pyme/callbacks.py \
	$(srcdir)/pyme/constants \
	$(srcdir)/pyme/core.py \
	$(srcdir)/pyme/errors.py \
	$(srcdir)/pyme/__init__.py \
	$(srcdir)/pyme/results.py \
	$(srcdir)/pyme/util.py

# For VPATH builds we need to copy some files because Python's
# distutils are not VPATH-aware.
copystamp: $(COPY_FILES) $(COPY_FILES_PYME)
	if test "$(srcdir)" != "$(builddir)" ; then \
	  cp -R $(COPY_FILES) . ; \
	  cp -R $(COPY_FILES_PYME) pyme ; \
	fi
	touch $@

all-local: copystamp
	for PYTHON in $(PYTHONS); do \
	  CFLAGS="$(CFLAGS) -I$(top_srcdir)" \
	    $$PYTHON setup.py build --verbose ; \
	done

dist/pyme3-$(VERSION).tar.gz dist/pyme3-$(VERSION).tar.gz.asc: copystamp
	CFLAGS="$(CFLAGS) -I$(top_srcdir)" \
	  $(PYTHON) setup.py sdist --verbose
	gpg2 --detach-sign --armor dist/pyme3-$(VERSION).tar.gz

.PHONY: sdist
sdist: dist/pyme3-$(VERSION).tar.gz dist/pyme3-$(VERSION).tar.gz.asc

.PHONY: upload
upload: dist/pyme3-$(VERSION).tar.gz dist/pyme3-$(VERSION).tar.gz.asc
	twine upload $^

CLEANFILES = gpgme.h errors.i gpgme_wrap.c pyme/gpgme.py \
	  copystamp

# Remove the rest.
#
# 'make distclean' clears the write bit, breaking rm -rf.  Fix the
# permissions.
clean-local:
	rm -rf -- build
	if test "$(srcdir)" != "$(builddir)" ; then \
	  find . -type d ! -perm -200 -exec chmod u+w {} ';' ; \
	  for F in $(COPY_FILES); do rm -rf -- `basename $$F` ; done ; \
	  for F in $(COPY_FILES_PYME); do \
	      rm -rf -- pyme/`basename $$F` ; \
	  done ; \
	fi

install-exec-local:
	rm -f install_files.txt
	for PYTHON in $(PYTHONS); do \
	  $$PYTHON setup.py install \
	  --prefix $(DESTDIR)$(prefix) \
	  --record files.txt \
	  --verbose ; \
	  cat files.txt >> install_files.txt ; \
	  rm files.txt ; \
	done
	$(MKDIR_P) $(DESTDIR)$(pythondir)/pyme
	mv install_files.txt $(DESTDIR)$(pythondir)/pyme

uninstall-local:
	xargs <$(DESTDIR)$(pythondir)/pyme/install_files.txt -- rm -rf --
	rm -rf -- $(DESTDIR)$(pythondir)/pyme
