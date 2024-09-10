# doc - Automake template
# Copyright (C) 2001, 2004 g10 Code GmbH
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

## Process this file with automake to produce Makefile.in

DISTCLEANFILES = gpgme.tmp yat2m-stamp.tmp yat2m-stamp $(myman_pages)
CLEANFILES = mkdefsinc defs.inc

EXTRA_DIST = module-overview.sk HACKING DCO ChangeLog-2011 \
             mkdefsinc.c defsincdate \
             examples/gpgme-mozilla.json examples/gpgme-chrome.json

BUILT_SOURCES = defsincdate defs.inc

YAT2M_OPTIONS = -I $(srcdir) --release "GPGME @PACKAGE_VERSION@"

myman_sources = gpgme-json.texi
myman_pages = gpgme-json.1

man_MANS = $(myman_pages)

info_TEXINFOS = gpgme.texi
gpgme_TEXINFOS = uiserver.texi lesser.texi gpl.texi gpgme-json.texi

gpgme.texi : defs.inc

mkdefsinc: mkdefsinc.c Makefile $(top_builddir)/conf/config.h
	$(CC_FOR_BUILD) -I. -I$(top_builddir)/conf  -I$(srcdir) \
	   $(AM_CPPFLAGS) -o $@ $(srcdir)/mkdefsinc.c

yat2m-stamp: $(myman_sources) defs.inc
	@rm -f yat2m-stamp.tmp
	@touch yat2m-stamp.tmp
	incd="`test -f defsincdate || echo '$(srcdir)/'`defsincdate"; \
	for file in $(myman_sources) ; do \
              $(YAT2M) $(YAT2M_OPTIONS) --store \
                  --date "`cat $$incd 2>/dev/null`" \
	          `test -f '$$file' || echo '$(srcdir)/'`$$file ; done
	@mv -f yat2m-stamp.tmp $@

$(myman_pages) : yat2m-stamp defs.inc
	@if test -f $@; then :; else \
            trap 'rm -rf yat2m-stamp yat2m-lock' 1 2 13 15; \
               if mkdir yat2m-lock 2>/dev/null; then \
                 rm -f yat2m-stamp; \
                 $(MAKE) $(AM_MAKEFLAGS) yat2m-stamp; \
                 rmdir yat2m-lock; \
               else \
                 while test -d yat2m-lock; do sleep 1; done; \
                 test -f yat2m-stamp; exit $$?; \
               fi; \
             fi

dist-hook: defsincdate

defsincdate: $(gpgme_TEXINFOS) $(info_TEXINFOS)
	: >defsincdate ; \
	if test -e $(top_srcdir)/.git; then \
	  (cd $(srcdir) && git log -1 --format='%ct' -- \
             $(info_TEXINFOS) $(gpgme_TEXINFOS) 2>/dev/null) >>defsincdate; \
	fi

defs.inc: defsincdate Makefile mkdefsinc
	incd="`test -f defsincdate || echo '$(srcdir)/'`defsincdate"; \
	./mkdefsinc -C $(srcdir) --date "`cat $$incd 2>/dev/null`" \
	    $(info_TEXINFOS) $(gpgme_TEXINFOS) >$@


online: gpgme.html gpgme.pdf
	set -e; \
	echo "Uploading current manuals to www.gnupg.org ..."; \
        user=werner ; \
	(cd gpgme.html && rsync -vr --exclude='.svn' .  \
	  $${user}@ftp.gnupg.org:webspace/manuals/gpgme/ ); \
        rsync -v gpgme.pdf $${user}@ftp.gnupg.org:webspace/manuals/
