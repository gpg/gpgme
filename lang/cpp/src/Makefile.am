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

libgpgmepp_la_SOURCES = $(main_sources) context_vanilla.cpp

AM_CPPFLAGS = @GPG_ERROR_CFLAGS@ @LIBASSUAN_CFLAGS@

libgpgmepp_la_LIBADD = ../../../src/libgpgme.la @LIBASSUAN_LIBS@
