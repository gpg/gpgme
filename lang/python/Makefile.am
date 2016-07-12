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
	helpers.c helpers.h \
	gpgme-h-clean.py \
	examples \
	pyme

SUBDIRS = tests

COPY_FILES = \
	$(srcdir)/gpgme.i \
	$(srcdir)/README \
	$(srcdir)/MANIFEST.in \
	$(srcdir)/gpgme-h-clean.py \
	$(srcdir)/pyme \
	$(srcdir)/examples \
	$(srcdir)/helpers.c $(srcdir)/helpers.h

# For VPATH builds we need to copy some files because Python's
# distutils are not VPATH-aware.
copystamp: $(COPY_FILES)
	if test "$(srcdir)" != "$(builddir)" ; then cp -r $^ . ; fi
	touch $@

all-local: copystamp
	CFLAGS="$(CFLAGS) -I$(top_srcdir)" \
	  $(PYTHON) setup.py build --verbose

dist/pyme3-$(VERSION).tar.gz dist/pyme3-$(VERSION).tar.gz.asc: copystamp
	CFLAGS="$(CFLAGS) -I$(top_srcdir)" \
	  $(PYTHON) setup.py sdist --verbose
	gpg2 --detach-sign --armor dist/pyme3-$(VERSION).tar.gz

.PHONY: sdist
sdist: dist/pyme3-$(VERSION).tar.gz dist/pyme3-$(VERSION).tar.gz.asc

.PHONY: upload
upload: dist/pyme3-$(VERSION).tar.gz dist/pyme3-$(VERSION).tar.gz.asc
	twine upload $^

CLEANFILES = gpgme.h errors.i gpgme_wrap.c pyme/pygpgme.py \
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
	fi

install-exec-local:
	$(PYTHON) setup.py install \
	  --prefix $(DESTDIR)$(prefix) \
	  --record $(DESTDIR)$(pythondir)/pyme/install_files.txt \
	  --verbose

uninstall-local:
	xargs <$(DESTDIR)$(pythondir)/pyme/install_files.txt -- rm -rf --
	rm -rf -- $(DESTDIR)$(pythondir)/pyme
