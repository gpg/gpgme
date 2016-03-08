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
lib_LTLIBRARIES = libqgpgme.la
EXTRA_DIST = QGpgmeConfig.cmake.in.in QGpgmeConfigVersion.cmake.in

qgpgme_sources = \
    dataprovider.cpp

qgpgme_headers = \
    dataprovider.h qgpgme_export.h

qgpgmeincludedir = $(includedir)/qgpgme
qgpgmeinclude_HEADERS = $(qgpgme_headers)

libqgpgme_la_SOURCES = $(qgpgme_sources) $(qgpgme_headers)

AM_CPPFLAGS = @GPGME_QT_CFLAGS@ @GPG_ERROR_CFLAGS@ @LIBASSUAN_CFLAGS@ \
              -DBUILDING_QGPGME -I$(top_srcdir)/lang/cpp/src

libqgpgme_la_LIBADD = ../../cpp/src/libgpgmepp.la ../../../src/libgpgme.la \
                       @LIBASSUAN_LIBS@ @GPGME_QT_LIBS@
libqgpgme_la_LDFLAGS = -version-info \
    @LIBQGPGME_LT_CURRENT@:@LIBQGPGME_LT_REVISION@:@LIBQGPGME_LT_AGE@

if HAVE_W32_SYSTEM
libsuffix=.dll.a
else
libsuffix=.so
endif

QGpgmeConfig.cmake: QGpgmeConfig.cmake.in
	sed -e 's|[@]resolved_libdir@|$(libdir)|g' < "$<" > "$@"
	sed -e 's|[@]libsuffix@|$(libsuffix)|g' < "$@" > "$@".2
	mv "$@".2 "$@"

install-cmake-files: QGpgmeConfig.cmake QGpgmeConfigVersion.cmake
	-$(INSTALL) -d $(DESTDIR)$(libdir)/cmake/Gpgmepp
	$(INSTALL) QGpgmeConfig.cmake \
        $(DESTDIR)$(libdir)/cmake/Gpgmepp/QGpgmeConfig.cmake
	$(INSTALL) QGpgmeConfigVersion.cmake \
        $(DESTDIR)$(libdir)/cmake/Gpgmepp/QGpgmeConfigVersion.cmake

uninstall-cmake-files:
	-rm $(DESTDIR)$(libdir)/cmake/Gpgmepp/QGpgmeConfigVersion.cmake
	-rm $(DESTDIR)$(libdir)/cmake/Gpgmepp/QGpgmeConfig.cmake
	-rmdir $(DESTDIR)$(libdir)/cmake/Gpgmepp/

install-data-local: install-cmake-files

uninstall-local: uninstall-cmake-files
