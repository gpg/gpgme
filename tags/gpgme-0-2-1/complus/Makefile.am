# Copyright (C) 2000 Werner Koch (dd9jn)
# Copyright (C) 2001 g10 Code GmbH
# 
# This file is part of GPGME.
# 
# GPGME is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# GPGME is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

## Process this file with automake to produce Makefile.in

EXTRA_DIST = WINE-LICENSE WINE-AUTHORS

# No need to install this becuase we are cross-compiling anyway.
noinst_PROGRAMS = gpgcom

INCLUDES = -I$(top_srcdir)/jnlib
LDADD = -L ../jnlib -ljnlib 

comheaders = obj_base.h basetsd.h guiddef.h  wtypes.h

gpgcom_SOURCES = main.c main.h \
		$(comheaders) \
		ignupg.c ignupg.h 


