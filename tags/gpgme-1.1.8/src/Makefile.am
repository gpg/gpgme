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
# License along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

## Process this file with automake to produce Makefile.in

# Note: moc_kdpipeiodevice should actually be a dependcy below.
EXTRA_DIST = gpgme-config.in gpgme.m4 mkstatus libgpgme.vers \
	     gpgme.h.in versioninfo.rc.in gpgme.def moc_kdpipeiodevice.cpp
BUILT_SOURCES = status-table.h
MOSTLYCLEANFILES = status-table.h
bin_SCRIPTS = gpgme-config
m4datadir = $(datadir)/aclocal
m4data_DATA = gpgme.m4
include_HEADERS = gpgme.h

if HAVE_PTHREAD
ltlib_gpgme_pthread = libgpgme-pthread.la
else
ltlib_gpgme_pthread =
endif
if HAVE_PTH
ltlib_gpgme_pth = libgpgme-pth.la
else
ltlib_gpgme_pth =
endif

if BUILD_W32_GLIB
ltlib_gpgme_glib = libgpgme-glib.la
else
ltlib_gpgme_glib =
endif

if BUILD_W32_QT
ltlib_gpgme_qt = libgpgme-qt.la
else
ltlib_gpgme_qt =
endif

lib_LTLIBRARIES = libgpgme.la $(ltlib_gpgme_glib) $(ltlib_gpgme_qt) \
	$(ltlib_gpgme_pthread) $(ltlib_gpgme_pth)

if HAVE_LD_VERSION_SCRIPT
libgpgme_version_script_cmd = -Wl,--version-script=$(srcdir)/libgpgme.vers
else
libgpgme_version_script_cmd =
endif

if BUILD_ASSUAN
assuan_cppflags = -I$(top_srcdir)/assuan
assuan_libobjs = ../assuan/libassuan.la
else
assuan_cppflags =
assuan_libobjs =
endif

if HAVE_DOSISH_SYSTEM
system_components = w32-util.c w32-sema.c
system_components_not_extra = w32-io.c
else
system_components = ath.h posix-util.c posix-sema.c posix-io.c
system_components_not_extra =
endif

if HAVE_GPGSM
gpgsm_components = engine-gpgsm.c
else
gpgsm_components =
endif

if HAVE_GPGCONF
gpgconf_components = engine-gpgconf.c
else
gpgconf_components =
endif

# These are the source files common to all library versions.  We used
# to build a non-installed library for that, but that does not work
# correctly on all platforms (in particular, one can not specify the
# right linking order with libtool, as the non-installed version has
# unresolved symbols to the thread module.
main_sources =								\
	gpgme.h util.h conversion.c get-env.c context.h ops.h		\
	data.h data.c data-fd.c data-stream.c data-mem.c data-user.c	\
	data-compat.c							\
	signers.c sig-notation.c					\
	wait.c wait-global.c wait-private.c wait-user.c wait.h		\
	op-support.c							\
	encrypt.c encrypt-sign.c decrypt.c decrypt-verify.c verify.c	\
	sign.c passphrase.c progress.c					\
	key.c keylist.c trust-item.c trustlist.c			\
	import.c export.c genkey.c delete.c edit.c getauditlog.c        \
	engine.h engine-backend.h engine.c rungpg.c status-table.h	\
	$(gpgsm_components) $(gpgconf_components) gpgconf.c		\
	sema.h priv-io.h $(system_components)				\
	debug.c debug.h gpgme.c version.c error.c

libgpgme_la_SOURCES = $(main_sources)					\
	ath.h ath.c $(system_components_not_extra) 
libgpgme_pthread_la_SOURCES = $(main_sources)				\
	ath.h ath-pthread.c $(system_components_not_extra)
libgpgme_pth_la_SOURCES = $(main_sources)				\
	ath.h ath-pth.c $(system_components_not_extra)

if BUILD_W32_GLIB
libgpgme_glib_la_SOURCES = $(main_sources) ath.h ath.c w32-glib-io.c
endif

if BUILD_W32_QT
libgpgme_qt_la_SOURCES = $(main_sources) ath.h ath.c w32-qt-io.cpp \
	kdpipeiodevice.h kdpipeiodevice.cpp kdpipeiodevice.moc
# FIXME: Add extra depedency: moc_kdpipeiodevice.cpp

# These are built sources (normally).
# moc_kdpipeiodevice.cpp: kdpipeiodevice.h
#	$(MOC4) -o $@ $<
#
# kdpipeiodevice.moc: kdpipeiodevice.cpp
#	$(MOC4) -o $@ $<
endif

# We use a global CFLAGS and CPPFLAGS setting for all library
# versions, because then every object file is only compiled once.
AM_CPPFLAGS = $(assuan_cppflags) @GPG_ERROR_CFLAGS@ @PTH_CPPFLAGS@ \
	@QT4_CORE_CFLAGS@
AM_CFLAGS = @PTH_CFLAGS@ @GLIB_CFLAGS@ @QT4_CORE_CFLAGS@

if HAVE_W32_SYSTEM

# Windows provides us with an endless stream of Tough Love.  To spawn
# processes with a controlled set of inherited handles, we need a
# wrapper process.
libexec_PROGRAMS = gpgme-w32spawn


LTRCCOMPILE = $(LIBTOOL) --mode=compile $(RC) \
     `echo $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) | \
     sed -e 's/-I/--include-dir /g;s/-D/--define /g'`

SUFFIXES: .rc .lo

.rc.lo:
	$(LTRCCOMPILE) -i $< -o $@

gpgme_res = versioninfo.lo
gpgme_res_ldflag = -Wl,.libs/versioninfo.o

no_undefined = -no-undefined
export_symbols = -export-symbols $(srcdir)/gpgme.def

install-def-file:
	$(INSTALL) $(srcdir)/gpgme.def $(DESTDIR)$(libdir)/gpgme.def

uninstall-def-file:
	-rm $(DESTDIR)$(libdir)/gpgme.def

gpgme_deps = $(gpgme_res) gpgme.def

else
gpgme_res =
gpgme_res_ldflag =
no_undefined =
export_symbols =
install-def-file:
uninstall-def-file:

gpgme_deps =
endif

libgpgme_la_LDFLAGS = $(gpgme_res_ldflag) $(no_undefined) $(export_symbols) \
	$(libgpgme_version_script_cmd) -version-info \
	@LIBGPGME_LT_CURRENT@:@LIBGPGME_LT_REVISION@:@LIBGPGME_LT_AGE@
libgpgme_la_DEPENDENCIES = $(assuan_libobjs) \
	@LTLIBOBJS@ $(srcdir)/libgpgme.vers $(gpgme_deps)
libgpgme_la_LIBADD = $(assuan_libobjs) @LTLIBOBJS@ \
	@GPG_ERROR_LIBS@ @NETLIBS@

libgpgme_pthread_la_LDFLAGS = $(libgpgme_version_script_cmd) -version-info \
	@LIBGPGME_LT_CURRENT@:@LIBGPGME_LT_REVISION@:@LIBGPGME_LT_AGE@
libgpgme_pthread_la_DEPENDENCIES = $(assuan_libobjs) \
	@LTLIBOBJS@ $(srcdir)/libgpgme.vers
libgpgme_pthread_la_LIBADD = $(assuan_libobjs) @LTLIBOBJS@ \
	-lpthread @GPG_ERROR_LIBS@ @NETLIBS@

libgpgme_pth_la_LDFLAGS = @PTH_LDFLAGS@ \
	$(libgpgme_version_script_cmd) -version-info \
	@LIBGPGME_LT_CURRENT@:@LIBGPGME_LT_REVISION@:@LIBGPGME_LT_AGE@
libgpgme_pth_la_DEPENDENCIES = $(assuan_libobjs) \
	@LTLIBOBJS@ $(srcdir)/libgpgme.vers
libgpgme_pth_la_LIBADD = $(assuan_libobjs) @LTLIBOBJS@ \
	@PTH_LIBS@ @GPG_ERROR_LIBS@ @NETLIBS@

if BUILD_W32_GLIB
libgpgme_glib_la_LDFLAGS = $(gpgme_res_ldflag) $(no_undefined) \
	$(export_symbols) $(libgpgme_version_script_cmd) -version-info \
	@LIBGPGME_LT_CURRENT@:@LIBGPGME_LT_REVISION@:@LIBGPGME_LT_AGE@
libgpgme_glib_la_DEPENDENCIES = $(assuan_libobjs) \
	@LTLIBOBJS@ $(srcdir)/libgpgme.vers $(gpgme_deps)
libgpgme_glib_la_LIBADD = $(assuan_libobjs) @LTLIBOBJS@ \
	@GPG_ERROR_LIBS@ @GLIB_LIBS@ @NETLIBS@
endif

if BUILD_W32_QT
libgpgme_qt_la_LDFLAGS = $(gpgme_res_ldflag) $(no_undefined) \
	$(export_symbols) $(libgpgme_version_script_cmd) -version-info \
	@LIBGPGME_LT_CURRENT@:@LIBGPGME_LT_REVISION@:@LIBGPGME_LT_AGE@
libgpgme_qt_la_DEPENDENCIES = $(assuan_libobjs) \
	@LTLIBOBJS@ $(srcdir)/libgpgme.vers $(gpgme_deps)
libgpgme_qt_la_LIBADD = $(assuan_libobjs) @LTLIBOBJS@ \
	@GPG_ERROR_LIBS@ @QT4_CORE_LIBS@ @NETLIBS@
endif

status-table.h : gpgme.h
	$(srcdir)/mkstatus < $(builddir)/gpgme.h > status-table.h

install-data-local: install-def-file

uninstall-local: uninstall-def-file
