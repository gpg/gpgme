# configure.in  for GPGME
# Copyright (C) 2000 Werner Koch (dd9jn)
# Copyright (C) 2001 g10 Code GmbH
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
 
# (Process this file with autoconf to produce a configure script.)

AC_INIT(gpgme, 0.2.3a, [gnupg-devel@gnupg.org])
AC_PREREQ(2.52)
AC_REVISION($Revision$)

AC_CONFIG_SRCDIR(gpgme/gpgme.h)
AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE(gpgme, 0.2.3a)
AM_MAINTAINER_MODE

AC_PROG_CC

# Version numbers (Remember to change them just before a release.)
#   (Interfaces removed:    CURRENT++, AGE=0, REVISION=0)
#   (Interfaces added:      CURRENT++, AGE++, REVISION=0)
#   (No interfaces changed:                   REVISION++)
# XXXX new functions
LIBGPGME_LT_CURRENT=4
LIBGPGME_LT_AGE=4
LIBGPGME_LT_REVISION=0
NEED_GPG_VERSION=1.0.6
##############################################

AC_SUBST(LIBGPGME_LT_CURRENT)
AC_SUBST(LIBGPGME_LT_AGE)
AC_SUBST(LIBGPGME_LT_REVISION)
AC_DEFINE_UNQUOTED(NEED_GPG_VERSION, "$NEED_GPG_VERSION")

dnl Don't default to build static libs.
dnl AC_DISABLE_STATIC
AC_PROG_LIBTOOL

GPG_DEFAULT=no
GPGSM_DEFAULT=no
component_system=None
case "${target}" in
    *-*-mingw32* | i?86-emx-os2 | i?86-*-os2*emx | i?86-*-msdosdjgpp* )
        # special stuff for Windoze NT
        # OS/2 with the EMX environment
        # DOS with the DJGPP environment
        AC_DEFINE(HAVE_DRIVE_LETTERS)
        AC_DEFINE(HAVE_DOSISH_SYSTEM)
        GPG_DEFAULT='c:\\gnupg\\gpg.exe'
        GPGSM_DEFAULT='c:\\gnupg\\gpgsm.exe'
        #component_system='COM+'
        ;;
    *)
dnl	# XXX: Probably use exec-prefix here?
dnl	GPG_DEFAULT='/usr/bin/gpg'
dnl	GPGSM_DEFAULT='/usr/bin/gpgsm'
	;;
esac

dnl
dnl Checks for libraries.
dnl

dnl FIXME: check whether Bonobo is installed

dnl
dnl Checks for header files.
dnl

dnl
dnl Checks for typedefs and structures.
dnl
GNUPG_CHECK_TYPEDEF(byte, HAVE_BYTE_TYPEDEF)
GNUPG_CHECK_TYPEDEF(ushort, HAVE_USHORT_TYPEDEF)
GNUPG_CHECK_TYPEDEF(ulong, HAVE_ULONG_TYPEDEF)
GNUPG_CHECK_TYPEDEF(u16, HAVE_U16_TYPEDEF)
GNUPG_CHECK_TYPEDEF(u32, HAVE_U32_TYPEDEF)

# We should not use them in this software;
# However jnlib/types.h needs them - so we take the easy way.
AC_CHECK_SIZEOF(unsigned short)
AC_CHECK_SIZEOF(unsigned int)
AC_CHECK_SIZEOF(unsigned long)

dnl
dnl Checks for compiler features.
dnl

if test "$GCC" = yes; then
    CFLAGS="$CFLAGS -Wall -Wcast-align -Wshadow -Wstrict-prototypes"
fi

dnl
dnl Checks for library functions.
dnl
dnl These are needed by libjnlib
AC_CHECK_FUNCS(memicmp stpcpy strlwr strtoul memmove stricmp)

dnl
dnl Checks for system services
dnl

NO_OVERRIDE=no
AC_ARG_WITH(gpg,
	    AC_HELP_STRING([--with-gpg=PATH], [use GnuPG binary at PATH]),
	    GPG=$withval, NO_OVERRIDE=yes)
if test "$NO_OVERRIDE" = "yes" || test "$GPG" = "yes"; then
  GPG=
  NO_OVERRIDE=yes
  if test "$cross_compiling" != "yes"; then
    AC_PATH_PROG(GPG, gpg)
  fi
  if test -z "$GPG"; then
    GPG="$GPG_DEFAULT"
  fi
fi
if test "$GPG" = no; then
  if test "$NO_OVERRIDE" = "yes"; then
    if test "$cross_compiling" != "yes"; then
      AC_MSG_WARN([Could not find GnuPG, install GnuPG or use --with-gpg=PATH to enable it])
    else
      AC_MSG_ERROR([Can not determine path to GnuPG when cross-compiling, use --with-gpg=PATH])
    fi
  fi
else
  AC_DEFINE_UNQUOTED(GPG_PATH, "$GPG")
fi
AM_CONDITIONAL(RUN_GPG_TESTS,
  [test "$cross_compiling" != "yes" && test -n "$GPG" && test -r "$GPG"])

NO_OVERRIDE=no
AC_ARG_WITH(gpgsm,
	    AC_HELP_STRING([--with-gpgsm=PATH], [use GpgSM binary at PATH]),
	    GPGSM=$withval, NO_OVERRIDE=yes)
if test "$NO_OVERRIDE" = "yes" || test "$GPGSM" = "yes"; then
  GPGSM=
  NO_OVERRIDE=yes
  if test "$cross_compiling" != "yes"; then
    AC_PATH_PROG(GPGSM, gpgsm)
  fi
  if test -z "$GPGSM"; then
    GPGSM="$GPGSM_DEFAULT"
  fi
fi
if test "$GPGSM" = no; then
  if test "$NO_OVERRIDE" = "yes"; then
    if test "$cross_compiling" != "yes"; then
      AC_MSG_WARN([Could not find GpgSM, install GpgSM or use --with-gpgsm=PATH to enable it])
    else
      AC_MSG_ERROR([Can not determine path to GpgSM when cross-compiling, use --with-gpgsm=PATH])
    fi
  fi
else
  AC_DEFINE_UNQUOTED(GPGSM_PATH, "$GPGSM")
fi
AM_CONDITIONAL(RUN_GPGSM_TESTS,
  [test "$cross_compiling" != "yes" && test -n "$GPGSM" && test -r "$GPGSM"])

dnl
dnl Create config files 
dnl

AM_CONDITIONAL(BUILD_COMPLUS, test "$component_system" = "COM+")
AM_CONDITIONAL(BUILD_BONOBO,  test "$component_system" = "Bonobo")

dnl Make the version number in gpgme/gpgme.h the same as the one here.
dnl (this is easier than to have a *.in file just for one substitution)
GNUPG_FIX_HDR_VERSION(gpgme/gpgme.h, GPGME_VERSION)

dnl Substitution used for gpgme-config 
GPGME_LIBS="-L${libdir} -lgpgme"
GPGME_CFLAGS=""
AC_SUBST(GPGME_LIBS)
AC_SUBST(GPGME_CFLAGS)

AC_CONFIG_FILES(Makefile jnlib/Makefile gpgme/Makefile tests/Makefile
		doc/Makefile bonobo/Makefile complus/Makefile)
AC_CONFIG_FILES(gpgme/gpgme-config, chmod +x gpgme/gpgme-config)
AC_OUTPUT

echo "
	GPGME v${VERSION} has been configured as follows:

        GnuPG version: min. $NEED_GPG_VERSION
	GnuPG path:    $GPG

	GpgSM path:    $GPGSM
"
