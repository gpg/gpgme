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
# License along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

## Process this file with automake to produce Makefile.in

DISTCLEANFILES = gpgme.tmp
CLEANFILES = mkdefsinc defs.inc

EXTRA_DIST = module-overview.sk HACKING DCO ChangeLog-2011 \
             mkdefsinc.c defsincdate

BUILT_SOURCES = defsincdate defs.inc


info_TEXINFOS = gpgme.texi
gpgme_TEXINFOS = uiserver.texi lesser.texi gpl.texi

gpgme.texi : defs.inc

mkdefsinc: mkdefsinc.c Makefile ../config.h
	$(CC_FOR_BUILD) -I. -I.. -I$(srcdir) $(AM_CPPFLAGS) \
	   -o $@ $(srcdir)/mkdefsinc.c

dist-hook: defsincdate

defsincdate: $(gpgme_TEXINFOS)
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

