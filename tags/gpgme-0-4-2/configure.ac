# configure.in for GPGME
# Copyright (C) 2000 Werner Koch (dd9jn)
# Copyright (C) 2001, 2002, 2003 g10 Code GmbH
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

# Version number: Remember to change it immediately *after* a release.
AC_INIT(gpgme, 0.4.2, [bug-gpgme@gnupg.org])
# LT Version numbers, remember to change them just *before* a release.
#   (Code changed:			REVISION++)
#   (Interfaces added/removed/changed:	CURRENT++, REVISION=0)
#   (Interfaces added:			AGE++)
#   (Interfaces removed:		AGE=0)
#
LIBGPGME_LT_CURRENT=11
LIBGPGME_LT_AGE=0
LIBGPGME_LT_REVISION=1
NEED_GPG_VERSION=1.2.2
NEED_GPGSM_VERSION=0.9.0
##############################################
AC_PREREQ(2.52)
AC_REVISION($Revision$)

PACKAGE=$PACKAGE_NAME
VERSION=$PACKAGE_VERSION

AC_CONFIG_SRCDIR(gpgme/gpgme.h)
AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE($PACKAGE, $VERSION)
AM_MAINTAINER_MODE

AH_VERBATIM([_GNU_SOURCE],
[/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif])

AH_VERBATIM([_REENTRANT],
[/* To allow the use of GPGME in multithreaded programs we have to use
  special features from the library.
  IMPORTANT: gpgme is not yet fully reentrant and you should use it
  only from one thread.  */
#ifndef _REENTRANT
# define _REENTRANT 1
#endif])


AC_PROG_CC


AC_SUBST(LIBGPGME_LT_CURRENT)
AC_SUBST(LIBGPGME_LT_AGE)
AC_SUBST(LIBGPGME_LT_REVISION)
AC_DEFINE_UNQUOTED(NEED_GPG_VERSION, "$NEED_GPG_VERSION",
				     [Min. needed GnuPG version.])
AC_DEFINE_UNQUOTED(NEED_GPGSM_VERSION, "$NEED_GPGSM_VERSION",
				       [Min. needed GPGSM version.])

AC_SUBST(PACKAGE)
AC_SUBST(VERSION)
AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE", [Name of this package])
AC_DEFINE_UNQUOTED(VERSION, "$VERSION", [Version of this package])

dnl Don't default to build static libs.
dnl AC_DISABLE_STATIC
AC_PROG_LIBTOOL

AC_CANONICAL_HOST
# For now we hardcode the use of version scripts.  It would be better
# to write a test for this or even implement this within libtool.
have_ld_version_script=no
case "${host}" in
    *-*-linux*)
	have_ld_version_script=yes
        ;;
    *-*-gnu*)
	have_ld_version_script=yes
        ;;
esac
AM_CONDITIONAL(HAVE_LD_VERSION_SCRIPT, test "$have_ld_version_script" = "yes")

GPG_DEFAULT=no
GPGSM_DEFAULT=no
component_system=None
case "${host}" in
    *-*-mingw32* | i?86-emx-os2 | i?86-*-os2*emx | i?86-*-msdosdjgpp* )
        # special stuff for Windoze NT
        # OS/2 with the EMX environment
        # DOS with the DJGPP environment
        AC_DEFINE(HAVE_DRIVE_LETTERS, ,
		  [Defined if we run on some of the PCDOS like systems (DOS,
		   Windoze, OS/2) with special properties like no file modes.])
        AC_DEFINE(HAVE_DOSISH_SYSTEM, ,
		  [Defined if the filesystem uses driver letters.])
	have_dosish_system=yes
        GPG_DEFAULT='c:\\gnupg\\gpg.exe'
	# XXX Assuan is not supported in this configuration.
	#GPGSM_DEFAULT='c:\\gnupg\\gpgsm.exe'
        #component_system='COM+'
        ;;
    *)
	AC_CHECK_PTH(1.2.0,,,no,have_pth=yes)
	if test "$have_pth" = yes; then
	  AC_DEFINE(HAVE_PTH, ,[Define if we have Pth.])
	  CFLAGS="$CFLAGS $PTH_CFLAGS"
	fi
	AC_CHECK_LIB(pthread,pthread_create,have_pthread=yes)
	if test "$have_pthread" = yes; then
	  AC_DEFINE(HAVE_PTHREAD, ,[Define if we have pthread.])
	fi

dnl	# XXX: Probably use exec-prefix here?
dnl	GPG_DEFAULT='/usr/bin/gpg'
dnl	GPGSM_DEFAULT='/usr/bin/gpgsm'
	;;
esac
AM_CONDITIONAL(HAVE_DOSISH_SYSTEM, test "$have_dosish_system" = "yes")
AM_CONDITIONAL(HAVE_PTH, test "$have_pth" = "yes")
AM_CONDITIONAL(HAVE_PTHREAD, test "$have_pthread" = "yes")

dnl
dnl Checks for header files.
dnl
AC_CHECK_HEADERS(sys/select.h)

dnl
dnl Type checks.
dnl

AC_CHECK_SIZEOF(unsigned int)

dnl
dnl Checks for compiler features.
dnl

if test "$GCC" = yes; then
    CFLAGS="$CFLAGS -Wall -Wcast-align -Wshadow -Wstrict-prototypes"
fi

dnl
dnl Checks for library functions.
dnl

AC_REPLACE_FUNCS(stpcpy)

AC_REPLACE_FUNCS(vasprintf)
if test "$ac_cv_func_vasprintf" != yes; then
  GNUPG_CHECK_VA_COPY
fi

# Note: fopencokie is only a dummy stub and not used.  
#       However some code in assuan/ links against it.
AC_REPLACE_FUNCS(fopencookie)

AM_PATH_GPG_ERROR(0.1,, AC_MSG_ERROR([libgpg-error was not found]))
AC_DEFINE(GPG_ERR_SOURCE_DEFAULT, GPG_ERR_SOURCE_GPGME,
          [The default error source for GPGME.])
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
  AC_DEFINE_UNQUOTED(GPG_PATH, "$GPG", [Path to the GnuPG binary.])
  AC_SUBST(GPG)
fi
AM_CONDITIONAL(RUN_GPG_TESTS,
  [test "$cross_compiling" != "yes" && test -n "$GPG" && test -r "$GPG"])
AC_SUBST(GPG_PATH)

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
  AC_DEFINE_UNQUOTED(GPGSM_PATH, "$GPGSM", [Path to the GPGSM binary.])
  AC_SUBST(GPGSM)
fi
AM_CONDITIONAL(HAVE_GPGSM, [test -n "$GPGSM" && test -r "$GPGSM"])
AM_CONDITIONAL(RUN_GPGSM_TESTS,
  [test "$cross_compiling" != "yes" && test -n "$GPGSM" && test -r "$GPGSM"])

dnl FIXME: Only build if supported.
AM_CONDITIONAL(BUILD_ASSUAN, test "$GPGSM" != "no")

AM_CONDITIONAL(BUILD_COMPLUS, test "$component_system" = "COM+")

dnl Make the version number in gpgme/gpgme.h the same as the one here.
dnl (this is easier than to have a *.in file just for one substitution)
GNUPG_FIX_HDR_VERSION(gpgme/gpgme.h, GPGME_VERSION)

dnl Substitution used for gpgme-config 
GPGME_CONFIG_LIBS="-lgpgme"
GPGME_CONFIG_CFLAGS=""
AC_SUBST(GPGME_CONFIG_LIBS)
AC_SUBST(GPGME_CONFIG_CFLAGS)

dnl Frob'da Variables
LTLIBOBJS=`echo "$LIB@&t@OBJS" |
           sed 's,\.[[^.]]* ,.lo ,g;s,\.[[^.]]*$,.lo,'`
AC_SUBST(LTLIBOBJS)

dnl
dnl Create config files 
dnl

AC_CONFIG_FILES(Makefile assuan/Makefile gpgme/Makefile
		tests/Makefile tests/gpg/Makefile tests/gpgsm/Makefile
		doc/Makefile complus/Makefile)
AC_CONFIG_FILES(gpgme/gpgme-config, chmod +x gpgme/gpgme-config)
AC_OUTPUT

echo "
	GPGME v${VERSION} has been configured as follows:

        GnuPG version: min. $NEED_GPG_VERSION
	GnuPG path:    $GPG

        GpgSM version: min. $NEED_GPGSM_VERSION
	GpgSM path:    $GPGSM
"
