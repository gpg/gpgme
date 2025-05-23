# Copyright (C) 2000 Werner Koch (dd9jn)
# Copyright (C) 2001, 2002, 2003, 2004, 2005, 2007 g10 Code GmbH
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

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = gpgme.pc gpgme-glib.pc

EXTRA_DIST = gpgme-config.in gpgme.m4 libgpgme.vers ChangeLog-2011 \
	     gpgme.h.in versioninfo.rc.in gpgme.def \
	     gpgme.pc.in gpgme-glib.pc.in

if USE_GPGRT_CONFIG
noinst_SCRIPTS = gpgme-config
else
bin_SCRIPTS = gpgme-config
endif
m4datadir = $(datadir)/aclocal
m4data_DATA = gpgme.m4
nodist_include_HEADERS = gpgme.h

bin_PROGRAMS = gpgme-tool gpgme-json

if BUILD_W32_GLIB
ltlib_gpgme_glib = libgpgme-glib.la
else
ltlib_gpgme_glib =
endif

lib_LTLIBRARIES = libgpgme.la $(ltlib_gpgme_glib)

if HAVE_LD_VERSION_SCRIPT
libgpgme_version_script_cmd = -Wl,--version-script=$(srcdir)/libgpgme.vers
else
libgpgme_version_script_cmd =
endif

if HAVE_DOSISH_SYSTEM
system_components = w32-util.c
system_components_not_extra = w32-io.c
else
system_components = posix-util.c posix-io.c
system_components_not_extra =
endif

if HAVE_UISERVER
uiserver_components = engine-uiserver.c
else
uiserver_components =
endif

# These are the source files common to all library versions.  We used
# to build a non-installed library for that, but that does not work
# correctly on all platforms (in particular, one can not specify the
# right linking order with libtool, as the non-installed version has
# unresolved symbols to the thread module.
main_sources =								\
	util.h conversion.c get-env.c context.h ops.h			\
	parsetlv.c parsetlv.h                                           \
	mbox-util.c mbox-util.h                                         \
	data.h data.c data-fd.c data-stream.c data-mem.c data-user.c	\
	data-estream.c                                                  \
	data-compat.c data-identify.c					\
	signers.c sig-notation.c					\
	wait.c wait-global.c wait-private.c wait-user.c wait.h		\
	op-support.c							\
	encrypt.c encrypt-sign.c decrypt.c decrypt-verify.c verify.c	\
	sign.c passphrase.c progress.c					\
	key.c keylist.c keysign.c tofupolicy.c	                        \
	revsig.c							\
	import.c export.c genkey.c delete.c edit.c getauditlog.c        \
	setexpire.c setownertrust.c genrandom.c				\
	opassuan.c passwd.c spawn.c assuan-support.c                    \
	engine.h engine-backend.h engine.c engine-gpg.c status-table.c	\
	engine-gpgsm.c engine-assuan.c engine-gpgconf.c                 \
	$(uiserver_components)						\
	engine-g13.c vfs-mount.c vfs-create.c			        \
	engine-spawn.c 	                                                \
	gpgconf.c queryswdb.c						\
	sema.h priv-io.h $(system_components) sys-util.h dirinfo.c	\
	debug.c debug.h gpgme.c version.c error.c

libgpgme_la_SOURCES = $(main_sources) $(system_components_not_extra)

if BUILD_W32_GLIB
libgpgme_glib_la_SOURCES = $(main_sources) w32-glib-io.c
endif

# We use a global CFLAGS setting for all libraries
# versions, because then every object file is only compiled once.
AM_CFLAGS = @LIBASSUAN_CFLAGS@ @GPG_ERROR_CFLAGS@ @GLIB_CFLAGS@

gpgme_tool_SOURCES = gpgme-tool.c argparse.c argparse.h
gpgme_tool_LDADD = libgpgme.la @LIBASSUAN_LIBS@ @GPG_ERROR_LIBS@

gpgme_json_SOURCES = gpgme-json.c json-core.c json-util.c \
                     json-common.h cJSON.c cJSON.h
gpgme_json_LDADD = -lm libgpgme.la $(GPG_ERROR_LIBS)


if HAVE_W32_SYSTEM
# Windows provides us with an endless stream of Tough Love.  To spawn
# processes with a controlled set of inherited handles, we need a
# wrapper process.
libexec_PROGRAMS = gpgme-w32spawn

gpgme_w32spawn_CFLAGS = -municode

RCCOMPILE = $(RC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES)
LTRCCOMPILE = $(LIBTOOL) --mode=compile --tag=RC $(RCCOMPILE)

SUFFIXES = .rc .lo

.rc.lo:
	$(LTRCCOMPILE) -i "$<" -o "$@"

gpgme_res = versioninfo.lo
no_undefined = -no-undefined
export_symbols = -export-symbols $(srcdir)/gpgme.def
extra_ltoptions = -XCClinker -static-libgcc
gpgme_w32_extra_libs = -lws2_32

install-def-file:
	-$(INSTALL) -d $(DESTDIR)$(libdir)
	$(INSTALL) $(srcdir)/gpgme.def $(DESTDIR)$(libdir)/gpgme.def

uninstall-def-file:
	-rm $(DESTDIR)$(libdir)/gpgme.def

gpgme_deps = $(gpgme_res) gpgme.def

else
gpgme_res =
no_undefined =
export_symbols =
extra_ltoptions =
install-def-file:
uninstall-def-file:

gpgme_deps =
endif

libgpgme_la_LDFLAGS = $(no_undefined) $(export_symbols) $(extra_ltoptions) \
	$(libgpgme_version_script_cmd) -version-info \
	@LIBGPGME_LT_CURRENT@:@LIBGPGME_LT_REVISION@:@LIBGPGME_LT_AGE@
libgpgme_la_DEPENDENCIES = @LTLIBOBJS@ $(srcdir)/libgpgme.vers $(gpgme_deps)
libgpgme_la_LIBADD = $(gpgme_res) @LIBASSUAN_LIBS@ @LTLIBOBJS@ \
	             @GPG_ERROR_LIBS@ $(gpgme_w32_extra_libs)

if BUILD_W32_GLIB
libgpgme_glib_la_LDFLAGS = \
        $(no_undefined) $(export_symbols) $(extra_ltoptions) \
        $(libgpgme_version_script_cmd) -version-info \
	@LIBGPGME_LT_CURRENT@:@LIBGPGME_LT_REVISION@:@LIBGPGME_LT_AGE@
libgpgme_glib_la_DEPENDENCIES =	@LTLIBOBJS@ \
	$(srcdir)/libgpgme.vers $(gpgme_deps)
libgpgme_glib_la_LIBADD = $(gpgme_res) @LIBASSUAN_LIBS@ @LTLIBOBJS@ \
	@GPG_ERROR_LIBS@ @GLIB_LIBS@ $(gpgme_w32_extra_libs)
endif

install-data-local: install-def-file

uninstall-local: uninstall-def-file
