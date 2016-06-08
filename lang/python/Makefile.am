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

EXTRA_DIST = README
SUBDIRS = tests

COPY_FILES = \
	$(srcdir)/README \
	$(srcdir)/pyme \
	$(srcdir)/helpers.c $(srcdir)/helpers.h

# Cleanup gpgme.h from deprecated functions and typedefs.
gpgme.h: ../../src/gpgme.h $(srcdir)/gpgme-h-clean.py
	$(PYTHON) $(srcdir)/gpgme-h-clean.py $< >$@

# For VPATH builds we need to copy some files because Python's
# distutils are not VPATH-aware.
copystamp: $(COPY_FILES)
	if test "$(srcdir)" != "$(builddir)" ; then cp -r $^ . ; fi
	touch $@

errors.i:
	sed -n -e \
	  '/GPG_ERR_[^ ]* =/s/ *\(.*\) = .*/%constant long \1 = \1;/p' \
	  `$(GPG_ERROR_CONFIG) --prefix`/include/gpg-error.h >$@

gpgme_wrap.c pyme/pygpgme.py: gpgme.i errors.i gpgme.h copystamp
	$(SWIG) -python -py3 $(SWIGOPT) \
	  -o $(builddir)/gpgme_wrap.c -outdir $(builddir)/pyme \
	  $<

all-local: gpgme_wrap.c pyme/pygpgme.py copystamp
	CFLAGS="$(CFLAGS) -I$(top_srcdir)" \
	  $(PYTHON) setup.py build --verbose

clean-local:
	rm -rf -- build gpgme.h errors.i gpgme_wrap.c pyme/pygpgme.py \
	  copystamp
	if test "$(srcdir)" != "$(builddir)" ; then \
	  rm -rf pyme helpers.c helpers.h ; \
	fi

install-exec-local:
	$(PYTHON) setup.py install \
	  --prefix $(DESTDIR)$(prefix) \
	  --record $(DESTDIR)$(pythondir)/pyme/install_files.txt \
	  --verbose

uninstall-local:
	xargs <$(DESTDIR)$(pythondir)/pyme/install_files.txt -- rm -rf --
	rm -rf -- $(DESTDIR)$(pythondir)/pyme
