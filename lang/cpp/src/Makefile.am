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

lib_LTLIBRARIES = libgpgmepp.la

main_sources = \
    exception.cpp context.cpp key.cpp trustitem.cpp data.cpp callbacks.cpp \
    eventloopinteractor.cpp editinteractor.cpp assuanresult.cpp \
    keylistresult.cpp keygenerationresult.cpp importresult.cpp \
    decryptionresult.cpp verificationresult.cpp \
    signingresult.cpp encryptionresult.cpp \
    engineinfo.cpp gpgsetexpirytimeeditinteractor.cpp \
    gpgsetownertrusteditinteractor.cpp gpgsignkeyeditinteractor.cpp \
    gpgadduserideditinteractor.cpp defaultassuantransaction.cpp \
    scdgetinfoassuantransaction.cpp gpgagentgetinfoassuantransaction.cpp \
    vfsmountresult.cpp configuration.cpp

gpgmepp_headers = \
    assuanresult.h configuration.h context.h data.h decryptionresult.h \
    defaultassuantransaction.h editinteractor.h encryptionresult.h \
    engineinfo.h error.h eventloopinteractor.h exception.h global.h \
    gpgadduserideditinteractor.h gpgagentgetinfoassuantransaction.h \
    gpgmefw.h gpgsetexpirytimeeditinteractor.h \
    gpgsetownertrusteditinteractor.h gpgsignkeyeditinteractor.h \
    importresult.h keygenerationresult.h key.h keylistresult.h \
    notation.h result.h scdgetinfoassuantransaction.h signingresult.h \
    trustitem.h verificationresult.h vfsmountresult.h gpgmepp_export.h

interface_headers= \
    interfaces/assuantransaction.h interfaces/dataprovider.h \
    interfaces/passphraseprovider.h interfaces/progressprovider.h

gpgmeppincludedir = $(includedir)/gpgme++
gpgmeppinclude_HEADERS = $(gpgmepp_headers)
nobase_gpgmeppinclude_HEADERS = $(interface_headers)

libgpgmepp_la_SOURCES = $(main_sources) $(gpgmepp_headers) context_vanilla.cpp \
                        $(interface_headers)

AM_CPPFLAGS = @GPG_ERROR_CFLAGS@ @LIBASSUAN_CFLAGS@ -DBUILDING_GPGMEPP

libgpgmepp_la_LIBADD = ../../../src/libgpgme.la @LIBASSUAN_LIBS@
