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

EXTRA_DIST = gpgme-config.in gpgme.m4 mkerrors mkstatus
BUILT_SOURCES = errors.c status-table.h
bin_SCRIPTS = gpgme-config
m4datadir = $(datadir)/aclocal
m4data_DATA = gpgme.m4
include_HEADERS = gpgme.h
lib_LTLIBRARIES = libgpgme.la

libgpgme_la_LDFLAGS = -version-info \
      @LIBGPGME_LT_CURRENT@:@LIBGPGME_LT_REVISION@:@LIBGPGME_LT_AGE@
if BUILD_ASSUAN
AM_CPPFLAGS = -I$(top_srcdir)/assuan
libgpgme_la_LIBADD = -L../assuan -lassuan
endif

libgpgme_la_SOURCES = \
	gpgme.h types.h \
	util.h util.c posix-util.c w32-util.c \
	context.h ops.h \
	data.c recipient.c signers.c \
        wait.c wait.h \
	encrypt.c \
	decrypt.c \
	decrypt-verify.c \
	verify.c \
	sign.c \
	passphrase.c \
        key.c key.h \
	keylist.c \
	trustlist.c \
	import.c \
        export.c \
	genkey.c \
	delete.c \
        rungpg.c rungpg.h status-table.h \
	engine-gpgsm.c engine-gpgsm.h \
	engine.c engine.h \
	sema.h posix-sema.c w32-sema.c \
	syshdr.h io.h posix-io.c w32-io.c \
	gpgme.c debug.c version.c errors.c

errors.c : gpgme.h
	$(srcdir)/mkerrors < $(srcdir)/gpgme.h > errors.c

status-table.h : rungpg.h
	$(srcdir)/mkstatus < $(srcdir)/rungpg.h > status-table.h
