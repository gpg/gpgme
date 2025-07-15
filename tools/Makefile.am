# Makefile.am - Makefile for GPGME tools.
# Copyright (C) 2025 g10 Code GmbH
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

GNUPGHOME=$(abs_builddir)

AM_CFLAGS = -I$(top_builddir)/src $(GPG_ERROR_CFLAGS)

LDADD = ../src/libgpgme.la $(GPG_ERROR_LIBS)

bin_PROGRAMS = gnupg-key-manage


gnupg_key_manage_SOURCES = gnupg-key-manage.c
