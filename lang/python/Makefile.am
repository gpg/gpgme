# Makefile.am for the Python bindings.
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

EXTRA_DIST = README.rst

# Cleanup gpgme.h from deprecated functions and typedefs.
gpgme.h: ../../src/gpgme.h
	$(PYTHON) $(srcdir)/gpgme-h-clean.py $< >$@

# For VPATH builds we need to copy some files because Python's
# distutils are not VPATH-aware.
copystamp: $(srcdir)/pyme $(srcdir)/helpers.c $(srcdir)/helpers.h
	if test "$(srcdir)" != "$(builddir)" ; then cp -a $^ . ; fi
	touch $@

gpgme_wrap.c pyme/pygpgme.py: gpgme.i gpgme.h copystamp
	$(SWIG) -python -py3 $(SWIGOPT) \
	  -o $(builddir)/gpgme_wrap.c -outdir $(builddir)/pyme \
	  $<

all-local: gpgme_wrap.c pyme/pygpgme.py copystamp
	$(PYTHON) $(srcdir)/setup.py build --verbose

clean-local:
	rm -rf -- build gpgme.h gpgme_wrap.c pyme/pygpgme.py copystamp
	if test "$(srcdir)" != "$(builddir)" ; then \
	  rm -rf pyme helpers.c helpers.h ; \
	fi

install-exec-local:
	$(PYTHON) $(srcdir)/setup.py install \
	  --prefix $(DESTDIR)$(prefix) \
	  --record $(DESTDIR)$(pythondir)/pyme/install_files.txt \
	  --verbose

uninstall-local:
	xargs <$(DESTDIR)$(pythondir)/pyme/install_files.txt -- rm -rf --
	rm -rf -- $(DESTDIR)$(pythondir)/pyme
