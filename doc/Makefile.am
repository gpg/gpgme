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

EXTRA_DIST = module-overview.sk HACKING ChangeLog-2011

info_TEXINFOS = gpgme.texi
gpgme_TEXINFOS = uiserver.texi lesser.texi gpl.texi

online: gpgme.html gpgme.pdf
	set -e; \
	echo "Uploading current manuals to www.gnupg.org ..."; \
        user=werner ; \
	(cd gpgme.html && rsync -vr --exclude='.svn' .  \
	  $${user}@cvs.gnupg.org:webspace/manuals/gpgme/ ); \
        rsync -v gpgme.pdf $${user}@cvs.gnupg.org:webspace/manuals/

