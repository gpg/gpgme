# Makefile.am for the Python bindings.
# Copyright (C) 2019 g10 Code GmbH
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

EXTRA_DIST = README rst src texinfo

if MAINTAINER_MODE

ORGSRCS = index.org gpgme-python-howto.org maintenance-mode.org \
	  short-history.org what-is-new.org what-was-new.org

# Make sure we have 'rst' and 'texinfo' dirs in build directory
.PHONY: the_doc_dirs gen_rst gen_texi

the_doc_dirs:
	@if test ! -d rst; then echo $(MKDIR_P) rst; $(MKDIR_P) rst; fi
	@if test ! -d texinfo; then echo $(MKDIR_P) texinfo; $(MKDIR_P) texinfo; fi

# Generate RST files from ORG
gen_rst:
	@for f in $(ORGSRCS); do if test ! -e rst/$${f%.org}.rst \
	  -o rst/$${f%.org}.rst -ot $(srcdir)/src/$$f; then \
	    echo pandoc -f org -t rst $(srcdir)/src/$$f -o rst/$${f%.org}.rst; \
	    pandoc -f org -t rst $(srcdir)/src/$$f -o rst/$${f%.org}.rst;      \
	  fi; \
	done

# Generate Texinfo files from ORG
gen_texi:
	@for f in $(ORGSRCS); do if test ! -e texinfo/$${f%.org}.texi \
	  -o texinfo/$${f%.org}.texi -ot $(srcdir)/src/$$f; then \
	    echo pandoc -f org -t texinfo $(srcdir)/src/$$f -o texinfo/$${f%.org}.texi; \
	    pandoc -f org -t texinfo $(srcdir)/src/$$f -o texinfo/$${f%.org}.texi;      \
	  fi; \
	done

all-local: gen_rst gen_texi

gen_rst gen_texi: the_doc_dirs

maintainer-clean-local:
	@for f in $(ORGSRCS); do \
	  echo rm -f rst/$${f%.org}.rst texinfo/$${f%.org}.texi; \
	  rm -f rst/$${f%.org}.rst texinfo/$${f%.org}.texi; \
	done
endif
