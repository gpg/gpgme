#  $Id$
#
#  Makefile.am - Automake specification file for GPGMEPLUG.
#                GPGMEPLUG is a GPGME based cryptography plug-in
#                following the common CRYPTPLUG specification.
#
#  Copyright (C) 2001 by Klar?lvdalens Datakonsult AB
#
#  GPGMEPLUG is free software; you can redistribute it and/or modify
#  it under the terms of GNU General Public License as published by
#  the Free Software Foundation; version 2 of the License.
#
#  GPGMEPLUG is distributed in the hope that it will be useful,
#  it under the terms of GNU General Public License as published by
#  the Free Software Foundation; version 2 of the License
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
#
## Process this file with automake to produce Makefile.in


INCLUDES = -I.. -I../gpgme -I$(top_srcdir)/include

#LDADD = ../gpgme/libgpgme.la
libgpgmeplug_la_LIBADD = ../gpgme/libgpgme.la

BUILT_SOURCES =

#noinst_LIBRARIES = libgpgmeplug.a
#noinst_LTLIBRARIES = libgpgmeplug.la

lib_LTLIBRARIES = libgpgmeplug.la


libgpgmeplug_la_LDFLAGS = -shared -Wl,-soname,libgpgmeplug.so

libgpgmeplug_la_SOURCES = gpgme.h \
	cryptplug.h \
	gpgmeplug.c

