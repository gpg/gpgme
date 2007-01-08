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

# Because WIDL does not yet fully support generation of typelibs, we
# have to distribute a binary type library.  To generate a new one,
# copy the idl file to a system with an install MIDL and run the
# command "midl /nocpp gpgcom.idl". Sorry, there is no other way yet.

EXTRA_DIST = gpgcom.idl gpgcom.tlb gpgcom.rc vbtest.html vbtest.vbs README

# No need to install this because we are cross-compiling anyway.
noinst_PROGRAMS = gpgcom tgpgcom 

INCLUDES = -I$(top_srcdir)/jnlib
LDADD = ../gpgme/libgpgme.la -L ../jnlib -ljnlib -lole32 -loleaut32 
gpgcom_LDADD = gpgcom_res.o $(LDADD)

gpgcom_SOURCES = gpgcom.c main.h \
		debug.c utf8.c \
		igpgme.h igpgme.c

tgpgcom_SOURCES = tgpgcom.c\
		debug.c \
		igpgme.h 

#regtlb_SOURCES = regtlb.c 
#guidgen_SOURCES = guidgen.c 

gpgcom_res.o: gpgcom.rc
	mingw32 windres $<  gpgcom_res.o

