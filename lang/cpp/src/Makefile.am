# Makefile.am for GPGMEPP.
# Copyright (C) 2016 Bundesamt für Sicherheit in der Informationstechnik
# Software engineering by Intevation GmbH
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

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = gpgmepp.pc

EXTRA_DIST = GpgmeppConfig.cmake.in.in GpgmeppConfigVersion.cmake.in \
             gpgmepp_version.h.in GpgmeppConfig-w32.cmake.in.in \
             gpgmepp.pc.in

lib_LTLIBRARIES = libgpgmepp.la

main_sources = \
    exception.cpp context.cpp key.cpp trustitem.cpp data.cpp callbacks.cpp \
    eventloopinteractor.cpp editinteractor.cpp \
    keylistresult.cpp keygenerationresult.cpp importresult.cpp \
    decryptionresult.cpp verificationresult.cpp \
    signingresult.cpp encryptionresult.cpp \
    engineinfo.cpp gpgsetexpirytimeeditinteractor.cpp \
    gpgsetownertrusteditinteractor.cpp gpgsignkeyeditinteractor.cpp \
    gpgadduserideditinteractor.cpp gpggencardkeyinteractor.cpp \
    gpgaddexistingsubkeyeditinteractor.cpp \
    gpgrevokekeyeditinteractor.cpp \
    defaultassuantransaction.cpp \
    scdgetinfoassuantransaction.cpp gpgagentgetinfoassuantransaction.cpp \
    statusconsumerassuantransaction.cpp \
    vfsmountresult.cpp configuration.cpp tofuinfo.cpp swdbresult.cpp \
    util.cpp

gpgmepp_headers = \
    configuration.h context.h data.h decryptionresult.h \
    defaultassuantransaction.h editinteractor.h encryptionresult.h \
    engineinfo.h error.h eventloopinteractor.h exception.h global.h \
    gpgadduserideditinteractor.h gpgagentgetinfoassuantransaction.h \
    gpgmefw.h gpgsetexpirytimeeditinteractor.h \
    gpgsetownertrusteditinteractor.h gpgsignkeyeditinteractor.h \
    gpggencardkeyinteractor.h \
    gpgaddexistingsubkeyeditinteractor.h \
    gpgrevokekeyeditinteractor.h \
    importresult.h keygenerationresult.h key.h keylistresult.h \
    notation.h result.h scdgetinfoassuantransaction.h signingresult.h \
    statusconsumerassuantransaction.h \
    trustitem.h verificationresult.h vfsmountresult.h gpgmepp_export.h \
    tofuinfo.h swdbresult.h

private_gpgmepp_headers = \
    result_p.h context_p.h util.h callbacks.h data_p.h

interface_headers= \
    interfaces/assuantransaction.h interfaces/dataprovider.h \
    interfaces/passphraseprovider.h interfaces/progressprovider.h \
    interfaces/statusconsumer.h

gpgmeppincludedir = $(includedir)/gpgme++
gpgmeppinclude_HEADERS = $(gpgmepp_headers)
nobase_gpgmeppinclude_HEADERS = $(interface_headers)
nodist_gpgmeppinclude_HEADERS = gpgmepp_version.h

libgpgmepp_la_SOURCES = $(main_sources) $(gpgmepp_headers) context_vanilla.cpp \
                        $(interface_headers) $(private_gpgmepp_headers)

AM_CPPFLAGS = @GPGME_CFLAGS@ \
              @GPGMEPP_CFLAGS@ @GPG_ERROR_CFLAGS@ \
              -DBUILDING_GPGMEPP -Wsuggest-override \
              -Wzero-as-null-pointer-constant

libgpgmepp_la_LIBADD = @GPGME_LIBS@
libgpgmepp_la_LDFLAGS = -no-undefined -version-info \
    @LIBGPGMEPP_LT_CURRENT@:@LIBGPGMEPP_LT_REVISION@:@LIBGPGMEPP_LT_AGE@

if HAVE_MACOS_SYSTEM
libsuffix=.dylib
else
libsuffix=.so
endif

copied_headers = $(gpgmepp_headers:%=gpgme++/%) $(interface_headers:%=gpgme++/%)

$(copied_headers): Makefile.am
	mkdir -p $(builddir)/gpgme++/interfaces
	echo -n "#include \"$(srcdir)" > "$@"
	echo -n "$@" | sed "s/gpgme++//" >> "$@"
	echo "\"" >> "$@"

if HAVE_W32_SYSTEM
GpgmeppConfig.cmake: GpgmeppConfig-w32.cmake.in
	sed -e 's|[@]resolved_bindir@|$(bindir)|g' < "$<" | \
	sed -e 's|[@]resolved_libdir@|$(libdir)|g' | \
	sed -e 's|[@]resolved_includedir@|$(includedir)|g' > $@
else
GpgmeppConfig.cmake: GpgmeppConfig.cmake.in
	sed -e 's|[@]resolved_libdir@|$(libdir)|g' < "$<" | \
	sed -e 's|[@]libsuffix@|$(libsuffix)|g' | \
	sed -e 's|[@]resolved_includedir@|$(includedir)|g' > $@
endif
install-cmake-files: GpgmeppConfig.cmake GpgmeppConfigVersion.cmake
	-$(INSTALL) -d $(DESTDIR)$(libdir)/cmake/Gpgmepp
	$(INSTALL) -m 644 GpgmeppConfig.cmake \
        $(DESTDIR)$(libdir)/cmake/Gpgmepp/GpgmeppConfig.cmake
	$(INSTALL) -m 644 GpgmeppConfigVersion.cmake \
        $(DESTDIR)$(libdir)/cmake/Gpgmepp/GpgmeppConfigVersion.cmake

uninstall-cmake-files:
	-rm $(DESTDIR)$(libdir)/cmake/Gpgmepp/GpgmeppConfigVersion.cmake
	-rm $(DESTDIR)$(libdir)/cmake/Gpgmepp/GpgmeppConfig.cmake
	-rmdir $(DESTDIR)$(libdir)/cmake/Gpgmepp/

install-data-local: install-cmake-files

uninstall-local: uninstall-cmake-files

BUILT_SOURCES = $(copied_headers)

CLEANFILES = GpgmeppConfig.cmake GpgmeppConfigVersion.cmake \
             gpgmepp_version.h GpgmeppConfig.cmake.in \
             $(copied_headers)
