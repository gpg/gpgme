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

COPY_FILES = \
	$(srcdir)/gpgme.i \
	$(srcdir)/README \
	$(srcdir)/MANIFEST.in \
	$(srcdir)/gpgme-h-clean.py \
	$(srcdir)/examples \
	$(srcdir)/helpers.c $(srcdir)/helpers.h $(srcdir)/private.h

COPY_FILES_GPG = \
	$(srcdir)/gpg/callbacks.py \
	$(srcdir)/gpg/constants \
	$(srcdir)/gpg/core.py \
	$(srcdir)/gpg/errors.py \
	$(srcdir)/gpg/__init__.py \
	$(srcdir)/gpg/results.py \
	$(srcdir)/gpg/util.py

# For VPATH builds we need to copy some files because Python's
# distutils are not VPATH-aware.
copystamp: $(COPY_FILES) $(COPY_FILES_GPG) data.h config.h
	if test "$(srcdir)" != "$(builddir)" ; then \
	  cp -R $(COPY_FILES) . ; \
	  cp -R $(COPY_FILES_GPG) gpg ; \
	fi
	touch $@

data.h:
	ln -s "$(top_srcdir)/src/data.h" .

config.h:
	ln -s "$(top_builddir)/config.h" .

all-local: copystamp
	for PYTHON in $(PYTHONS); do \
	  CFLAGS="$(CFLAGS)" \
	    $$PYTHON setup.py build --verbose ; \
	done

dist/gpg-$(VERSION).tar.gz dist/gpg-$(VERSION).tar.gz.asc: copystamp
	CFLAGS="$(CFLAGS)" \
	  $(PYTHON) setup.py sdist --verbose
	gpg2 --detach-sign --armor dist/gpg-$(VERSION).tar.gz

.PHONY: prepare
prepare: copystamp

.PHONY: sdist
sdist: dist/gpg-$(VERSION).tar.gz dist/gpg-$(VERSION).tar.gz.asc

.PHONY: upload
upload: dist/gpg-$(VERSION).tar.gz dist/gpg-$(VERSION).tar.gz.asc
	twine upload $^

CLEANFILES = gpgme.h errors.i gpgme_wrap.c gpg/gpgme.py \
	  data.h config.h copystamp

# Remove the rest.
#
# 'make distclean' clears the write bit, breaking rm -rf.  Fix the
# permissions.
clean-local:
	rm -rf -- build
	if test "$(srcdir)" != "$(builddir)" ; then \
	  find . -type d ! -perm -200 -exec chmod u+w {} ';' ; \
	  for F in $(COPY_FILES); do rm -rf -- `basename $$F` ; done ; \
	  for F in $(COPY_FILES_GPG); do \
	      rm -rf -- gpg/`basename $$F` ; \
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
	$(MKDIR_P) $(DESTDIR)$(pythondir)/gpg
	mv install_files.txt $(DESTDIR)$(pythondir)/gpg

uninstall-local:
	xargs <$(DESTDIR)$(pythondir)/gpg/install_files.txt -- rm -rf --
	rm -rf -- $(DESTDIR)$(pythondir)/gpg
