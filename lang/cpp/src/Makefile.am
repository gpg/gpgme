# Makefile.am for GPGMEPP.
# Copyright (C) 2016 Intevation GmbH
#
# This file is part of GPGMEPP.
#
# GPGME-CL is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# GPGME-CL is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA

EXTRA_DIST = GpgmeppConfig.cmake.in.in GpgmeppConfigVersion.cmake.in \
             gpgmepp_version.h.in

lib_LTLIBRARIES = libgpgmepp.la

main_sources = \
    exception.cpp context.cpp key.cpp trustitem.cpp data.cpp callbacks.cpp \
    eventloopinteractor.cpp editinteractor.cpp \
    keylistresult.cpp keygenerationresult.cpp importresult.cpp \
    decryptionresult.cpp verificationresult.cpp \
    signingresult.cpp encryptionresult.cpp \
    engineinfo.cpp gpgsetexpirytimeeditinteractor.cpp \
    gpgsetownertrusteditinteractor.cpp gpgsignkeyeditinteractor.cpp \
    gpgadduserideditinteractor.cpp defaultassuantransaction.cpp \
    scdgetinfoassuantransaction.cpp gpgagentgetinfoassuantransaction.cpp \
    vfsmountresult.cpp configuration.cpp tofuinfo.cpp

gpgmepp_headers = \
    configuration.h context.h data.h decryptionresult.h \
    defaultassuantransaction.h editinteractor.h encryptionresult.h \
    engineinfo.h error.h eventloopinteractor.h exception.h global.h \
    gpgadduserideditinteractor.h gpgagentgetinfoassuantransaction.h \
    gpgmefw.h gpgsetexpirytimeeditinteractor.h \
    gpgsetownertrusteditinteractor.h gpgsignkeyeditinteractor.h \
    importresult.h keygenerationresult.h key.h keylistresult.h \
    notation.h result.h scdgetinfoassuantransaction.h signingresult.h \
    trustitem.h verificationresult.h vfsmountresult.h gpgmepp_export.h \
    tofuinfo.h

private_gpgmepp_headers = \
    result_p.h context_p.h util.h callbacks.h data_p.h

interface_headers= \
    interfaces/assuantransaction.h interfaces/dataprovider.h \
    interfaces/passphraseprovider.h interfaces/progressprovider.h

gpgmeppincludedir = $(includedir)/gpgme++
gpgmeppinclude_HEADERS = $(gpgmepp_headers)
nobase_gpgmeppinclude_HEADERS = $(interface_headers)
nodist_include_HEADERS = gpgmepp_version.h

libgpgmepp_la_SOURCES = $(main_sources) $(gpgmepp_headers) context_vanilla.cpp \
                        $(interface_headers) $(private_gpgmepp_headers)

AM_CPPFLAGS = -I$(top_builddir)/src @GPG_ERROR_CFLAGS@ @LIBASSUAN_CFLAGS@ \
              -DBUILDING_GPGMEPP

libgpgmepp_la_LIBADD = ../../../src/libgpgme.la @LIBASSUAN_LIBS@
libgpgmepp_la_LDFLAGS = -version-info \
    @LIBGPGMEPP_LT_CURRENT@:@LIBGPGMEPP_LT_REVISION@:@LIBGPGMEPP_LT_AGE@

if HAVE_W32_SYSTEM
libsuffix=.dll.a
else
libsuffix=.so
endif

GpgmeppConfig.cmake: GpgmeppConfig.cmake.in
	sed -e 's|[@]resolved_libdir@|$(libdir)|g' < "$<" > "$@"
	sed -e 's|[@]libsuffix@|$(libsuffix)|g' < "$@" > "$@".2
	mv "$@".2 "$@"

install-cmake-files: GpgmeppConfig.cmake GpgmeppConfigVersion.cmake
	-$(INSTALL) -d $(DESTDIR)$(libdir)/cmake/Gpgmepp
	$(INSTALL) GpgmeppConfig.cmake \
        $(DESTDIR)$(libdir)/cmake/Gpgmepp/GpgmeppConfig.cmake
	$(INSTALL) GpgmeppConfigVersion.cmake \
        $(DESTDIR)$(libdir)/cmake/Gpgmepp/GpgmeppConfigVersion.cmake

uninstall-cmake-files:
	-rm $(DESTDIR)$(libdir)/cmake/Gpgmepp/GpgmeppConfigVersion.cmake
	-rm $(DESTDIR)$(libdir)/cmake/Gpgmepp/GpgmeppConfig.cmake
	-rmdir $(DESTDIR)$(libdir)/cmake/Gpgmepp/

install-data-local: install-cmake-files

uninstall-local: uninstall-cmake-files

CLEANFILES = GpgmeppConfig.cmake
