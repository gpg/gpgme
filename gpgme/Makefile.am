# Copyright (C) 2000 Werner Koch (dd9jn)
# Copyright (C) 2001, 2002, 2003 g10 Code GmbH
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

EXTRA_DIST = gpgme-config.in gpgme.m4 mkerrors mkstatus libgpgme.vers
BUILT_SOURCES = errors.c status-table.h
MOSTLYCLEANFILES = errors.c status-table.h
bin_SCRIPTS = gpgme-config
m4datadir = $(datadir)/aclocal
m4data_DATA = gpgme.m4
include_HEADERS = gpgme.h
lib_LTLIBRARIES = libgpgme.la

if HAVE_LD_VERSION_SCRIPT
libgpgme_version_script_cmd = -Wl,--version-script=$(srcdir)/libgpgme.vers
else
libgpgme_version_script_cmd =
endif

libgpgme_la_LDFLAGS = $(libgpgme_version_script_cmd) -version-info \
      @LIBGPGME_LT_CURRENT@:@LIBGPGME_LT_REVISION@:@LIBGPGME_LT_AGE@

if BUILD_ASSUAN
AM_CPPFLAGS = -I$(top_srcdir)/assuan
assuan_libobjs = ../assuan/libassuan.la
else
assuan_libobjs =
endif

if HAVE_PTHREAD
ath_components_pthread = ath-pthread.c
else
ath_components_pthread =
endif
if HAVE_PTH
ath_components_pth = ath-pth.c
else
ath_components_pth =
endif
ath_components = ath.h ath.c ${ath_components_pthread} ${ath_components_pth}

if HAVE_DOSISH_SYSTEM
system_components = w32-util.c w32-sema.c w32-io.c
else
system_components = ${ath_components} posix-util.c posix-sema.c posix-io.c
endif

if HAVE_GPGSM
gpgsm_components = engine-gpgsm.c
else
gpgsm_components =
endif

libgpgme_la_SOURCES =							\
	gpgme.h util.h conversion.c context.h ops.h			\
	data.h data.c data-fd.c data-stream.c data-mem.c data-user.c	\
	data-compat.c							\
	recipient.c signers.c						\
	wait.c wait-global.c wait-private.c wait-user.c wait.h		\
	op-support.c							\
	encrypt.c encrypt-sign.c decrypt.c decrypt-verify.c verify.c	\
	sign.c passphrase.c progress.c					\
	key.c key-cache.c keylist.c trust-item.c trustlist.c		\
	import.c export.c genkey.c delete.c edit.c			\
	engine.h engine-backend.h engine.c rungpg.c status-table.h	\
	${gpgsm_components} sema.h io.h ${system_components}		\
	debug.c debug.h gpgme.c version.c errors.c

libgpgme_la_DEPENDENCIES = ${assuan_libobjs} @LTLIBOBJS@ \
	$(srcdir)/libgpgme.vers

libgpgme_la_LIBADD = ${assuan_libobjs} @LTLIBOBJS@

errors.c : gpgme.h
	$(srcdir)/mkerrors < $(srcdir)/gpgme.h > errors.c

status-table.h : gpgme.h
	$(srcdir)/mkstatus < $(srcdir)/gpgme.h > status-table.h

