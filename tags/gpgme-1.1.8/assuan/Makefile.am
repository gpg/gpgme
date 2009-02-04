# Assuan Makefile
# Copyright (C) 2001, 2002, 2003 Free Software Foundation, Inc.
#
# This file is part of Assuan.
#
# Assuan is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# Assuan is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA 

## Process this file with automake to produce Makefile.in

EXTRA_DIST = mkerrors
INCLUDES = -I.. -I$(top_srcdir)/src
BUILT_SOURCES = assuan-errors.c
MOSTLYCLEANFILES = assuan-errors.c

noinst_LTLIBRARIES = libassuan.la

AM_CPPFLAGS = -D_ASSUAN_IN_GPGME_BUILD_ASSUAN

#libassuan_la_LDFLAGS =
libassuan_la_SOURCES = \
	assuan.h \
	assuan-defs.h \
	assuan-util.c \
	assuan-errors.c \
	assuan-buffer.c \
	assuan-handler.c \
	assuan-inquire.c \
	assuan-listen.c \
	assuan-connect.c \
	assuan-client.c \
	assuan-pipe-server.c \
	assuan-socket-server.c \
	assuan-pipe-connect.c \
	assuan-socket-connect.c  \
	assuan-uds.c \
	assuan-io.c \
	assuan-logging.c \
	assuan-socket.c

assuan-errors.c : assuan.h mkerrors
	$(srcdir)/mkerrors < $(srcdir)/assuan.h > assuan-errors.c
