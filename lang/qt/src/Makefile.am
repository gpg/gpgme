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
EXTRA_DIST = QGpgmeConfig.cmake.in.in QGpgmeConfigVersion.cmake.in \
             gpgme_backend_debug.h

qgpgme_sources = \
    dataprovider.cpp job.cpp qgpgmeadduseridjob.cpp \
    qgpgmebackend.cpp qgpgmechangeexpiryjob.cpp qgpgmechangeownertrustjob.cpp \
    qgpgmechangepasswdjob.cpp qgpgmedecryptjob.cpp \
    qgpgmedecryptverifyjob.cpp qgpgmedeletejob.cpp qgpgmedownloadjob.cpp \
    qgpgmeencryptjob.cpp qgpgmeexportjob.cpp qgpgmeimportfromkeyserverjob.cpp \
    qgpgmeimportjob.cpp qgpgmekeygenerationjob.cpp qgpgmekeylistjob.cpp \
    qgpgmelistallkeysjob.cpp qgpgmenewcryptoconfig.cpp \
    qgpgmerefreshkeysjob.cpp \
    qgpgmesecretkeyexportjob.cpp qgpgmesignencryptjob.cpp \
    qgpgmesignjob.cpp qgpgmesignkeyjob.cpp qgpgmeverifydetachedjob.cpp \
    qgpgmeverifyopaquejob.cpp threadedjobmixin.cpp \
    gpgme_backend_debug.cpp

qgpgme_headers= \
    adduseridjob.h \
    changeexpiryjob.h \
    changeownertrustjob.h \
    changepasswdjob.h \
    dataprovider.h \
    decryptjob.h \
    decryptverifyjob.h \
    downloadjob.h \
    encryptjob.h \
    exportjob.h \
    hierarchicalkeylistjob.h \
    job.h \
    multideletejob.h \
    protocol.h \
    qgpgme_export.h \
    qgpgmenewcryptoconfig.h \
    signjob.h \
    signkeyjob.h \
    signencryptjob.h \
    verifyopaquejob.h \
    refreshkeysjob.h \
    cryptoconfig.h \
    deletejob.h \
    importfromkeyserverjob.h \
    importjob.h \
    keygenerationjob.h \
    keylistjob.h \
    listallkeysjob.h \
    verifydetachedjob.h

private_qgpgme_headers = \
    qgpgme_export.h \
    abstractimportjob.h \
    protocol_p.h \
    qgpgmeadduseridjob.h \
    qgpgmebackend.h \
    qgpgmechangeexpiryjob.h \
    qgpgmechangeownertrustjob.h \
    qgpgmechangepasswdjob.h \
    qgpgmedecryptjob.h \
    qgpgmedecryptverifyjob.h \
    qgpgmedeletejob.h \
    qgpgmedownloadjob.h \
    qgpgmeencryptjob.h \
    qgpgmeexportjob.h \
    qgpgmeimportfromkeyserverjob.h \
    qgpgmeimportjob.h \
    qgpgmekeygenerationjob.h \
    qgpgmekeylistjob.h \
    qgpgmelistallkeysjob.h \
    qgpgmerefreshkeysjob.h \
    qgpgmesecretkeyexportjob.h \
    qgpgmesignencryptjob.h \
    qgpgmesignjob.h \
    qgpgmesignkeyjob.h \
    qgpgmeverifydetachedjob.h \
    qgpgmeverifyopaquejob.h \
    specialjob.h \
    threadedjobmixin.h

qgpgme_moc_sources = \
    abstractimportjob.moc \
    adduseridjob.moc \
    changeexpiryjob.moc \
    changeownertrustjob.moc \
    changepasswdjob.moc \
    decryptjob.moc \
    decryptverifyjob.moc \
    deletejob.moc \
    downloadjob.moc \
    encryptjob.moc \
    exportjob.moc \
    hierarchicalkeylistjob.moc \
    importfromkeyserverjob.moc \
    importjob.moc \
    job.moc \
    keygenerationjob.moc \
    keylistjob.moc \
    listallkeysjob.moc \
    multideletejob.moc \
    qgpgmeadduseridjob.moc \
    qgpgmechangeexpiryjob.moc \
    qgpgmechangeownertrustjob.moc \
    qgpgmechangepasswdjob.moc \
    qgpgmedecryptjob.moc \
    qgpgmedecryptverifyjob.moc \
    qgpgmedeletejob.moc \
    qgpgmedownloadjob.moc \
    qgpgmeencryptjob.moc \
    qgpgmeexportjob.moc \
    qgpgmeimportfromkeyserverjob.moc \
    qgpgmeimportjob.moc \
    qgpgmekeygenerationjob.moc \
    qgpgmekeylistjob.moc \
    qgpgmelistallkeysjob.moc \
    qgpgmerefreshkeysjob.moc \
    qgpgmesecretkeyexportjob.moc \
    qgpgmesignencryptjob.moc \
    qgpgmesignjob.moc \
    qgpgmesignkeyjob.moc \
    qgpgmeverifydetachedjob.moc \
    qgpgmeverifyopaquejob.moc \
    refreshkeysjob.moc \
    signencryptjob.moc \
    signjob.moc \
    signkeyjob.moc \
    specialjob.moc \
    verifydetachedjob.moc \
    verifyopaquejob.moc

qgpgmeincludedir = $(includedir)/qgpgme
qgpgmeinclude_HEADERS = $(qgpgme_headers)

libqgpgme_la_SOURCES = $(qgpgme_sources) $(qgpgme_headers) $(private_qgpgme_headers)

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

BUILT_SOURCES = $(qgpgme_moc_sources)

CLEANFILES = $(qgpgme_moc_sources) QGpgmeConfig.cmake

nodist_libqgpgme_la_SOURCES = $(qgpgme_moc_sources)

.h.moc:
	$(MOC) `test -f '$<' || echo '$(srcdir)/'`$< -o $@
