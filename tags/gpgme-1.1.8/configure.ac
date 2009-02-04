# configure.ac for GPGME
# Copyright (C) 2000 Werner Koch (dd9jn)
# Copyright (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008 g10 Code GmbH
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
 
# (Process this file with autoconf to produce a configure script.)
AC_PREREQ(2.59)
min_automake_version="1.10"

# Version number: Remember to change it immediately *after* a release.
#                 Make sure to run  "svn up" and "./autogen.sh --force"
#                  before a "make dist".  See below for the LT versions.
#
# The SVN version is usually the next intended release version with
# the string "-svnNNN" appended.  The reason for this is that tests for a
# specific feature can already be done under the assumption that the
# SVN version is the most recent one in a branch.  To disable the SVN
# version for the real release, set the my_issvn macro to no.
m4_define(my_version, [1.1.8])
m4_define(my_issvn, [no])

m4_define([svn_revision], m4_esyscmd([echo -n $( (svn info 2>/dev/null \
            || echo 'Revision: 0')|sed -n '/^Revision:/ {s/[^0-9]//gp;q;}')]))
AC_INIT([gpgme], 
        [my_version[]m4_if(my_issvn,[yes],[-svn[]svn_revision])],
        [bug-gpgme@gnupg.org])


# LT Version numbers, remember to change them just *before* a release.
#   (Code changed:			REVISION++)
#   (Interfaces added/removed/changed:	CURRENT++, REVISION=0)
#   (Interfaces added:			AGE++)
#   (Interfaces removed/changed:	AGE=0)
#
LIBGPGME_LT_CURRENT=17
# Subtract 2 from this value if you want to make the LFS transition an
# ABI break.  [Note to self: Remove this comment with the next regular break.]
LIBGPGME_LT_AGE=6
LIBGPGME_LT_REVISION=6

# If the API is changed in an incompatible way: increment the next counter.
GPGME_CONFIG_API_VERSION=1
##############################################


BUILD_REVISION=svn_revision
PACKAGE=$PACKAGE_NAME
VERSION=$PACKAGE_VERSION

AC_CONFIG_SRCDIR(src/gpgme.h.in)
dnl FIXME: Enable this with autoconf 2.59.
dnl AC_CONFIG_MACRO_DIR(m4)
AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE($PACKAGE, $VERSION)
AM_MAINTAINER_MODE
AC_CANONICAL_HOST

# Enable GNU extensions on systems that have them.
AC_GNU_SOURCE

AH_VERBATIM([_REENTRANT],
[/* To allow the use of GPGME in multithreaded programs we have to use
  special features from the library.
  IMPORTANT: gpgme is not yet fully reentrant and you should use it
  only from one thread.  */
#ifndef _REENTRANT
# define _REENTRANT 1
#endif])

AC_PROG_CC
AC_PROG_CXX

AC_SUBST(LIBGPGME_LT_CURRENT)
AC_SUBST(LIBGPGME_LT_AGE)
AC_SUBST(LIBGPGME_LT_REVISION)

AC_SUBST(PACKAGE)
AC_SUBST(VERSION)
AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE", [Name of this package])
AC_DEFINE_UNQUOTED(VERSION, "$VERSION", [Version of this package])

# Don't default to build static libs.
AC_DISABLE_STATIC
AC_LIBTOOL_WIN32_DLL
AC_LIBTOOL_RC
AC_PROG_LIBTOOL

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
    *-apple-darwin*)
        AC_DEFINE(_XOPEN_SOURCE, 500, Activate POSIX interface on MacOS X)
        ;;
esac

AM_CONDITIONAL(HAVE_LD_VERSION_SCRIPT, test "$have_ld_version_script" = "yes")

GPG_DEFAULT=no
GPGSM_DEFAULT=no
GPGCONF_DEFAULT=no
component_system=None
have_dosish_system=no
have_w32_system=no
build_w32_glib=no
build_w32_qt=no
case "${host}" in
    *-mingw32*)
        # special stuff for Windoze NT
	have_dosish_system=yes
        have_w32_system=yes
        GPG_DEFAULT='c:\\gnupg\\gpg.exe'
	GPGSM_DEFAULT='c:\\gnupg\\gpgsm.exe'
        GPGCONF_DEFAULT='c:\\gnupg\\gpgconf.exe'
        #component_system='COM+'

	AM_PATH_GLIB_2_0
	AC_ARG_ENABLE(w32-glib,
	    AC_HELP_STRING([--enable-w32-glib], [build GPGME Glib for W32]),
	    		   build_w32_glib=$enableval)

	# Check disabled, because the qt-dev packages in gpg4win do
	# not provide any support for cross compilation.
	# PKG_CHECK_MODULES(QT4_CORE, QtCore)

	# Use it like this:
	# ./configure --enable-w32-qt QT4_CORE_CFLAGS="..." QT4_CORE_LIBS="..."
	AC_SUBST(QT4_CORE_CFLAGS)
	AC_SUBST(QT4_CORE_LIBS)
	AC_ARG_ENABLE(w32-qt,
	    AC_HELP_STRING([--enable-w32-qt], [build GPGME Qt for W32]),
	    		   build_w32_qt=$enableval)
        ;;
    *)
	AC_CHECK_PTH(1.2.0,,,no,have_pth=yes)
	if test "$have_pth" = yes; then
	  AC_DEFINE(HAVE_PTH, ,[Define if we have Pth.])
	fi
	AC_CHECK_LIB(pthread,pthread_create,have_pthread=yes)
	if test "$have_pthread" = yes; then
	  AC_DEFINE(HAVE_PTHREAD, ,[Define if we have pthread.])
	fi

	# XXX: Probably use exec-prefix here?
#	GPG_DEFAULT='/usr/bin/gpg'
#	GPGSM_DEFAULT='/usr/bin/gpgsm'
#	GPGCONF_DEFAULT='/usr/bin/gpgconf'
	;;
esac

if test "$have_dosish_system" = yes; then
   AC_DEFINE(HAVE_DOSISH_SYSTEM,1,
             [Defined if we run on some of the PCDOS like systems 
              (DOS, Windoze. OS/2) with special properties like
              no file modes])
fi
AM_CONDITIONAL(HAVE_DOSISH_SYSTEM, test "$have_dosish_system" = yes)

if test "$have_w32_system" = yes; then
   AC_DEFINE(HAVE_W32_SYSTEM,1, [Defined if we run on a W32 API based system])
fi
AM_CONDITIONAL(HAVE_W32_SYSTEM, test "$have_w32_system" = yes)
AM_CONDITIONAL(BUILD_W32_GLIB, test "$build_w32_glib" = yes)
AM_CONDITIONAL(BUILD_W32_QT, test "$build_w32_qt" = yes)

AM_CONDITIONAL(HAVE_PTH, test "$have_pth" = "yes")
AM_CONDITIONAL(HAVE_PTHREAD, test "$have_pthread" = "yes")


# Checks for header files.
AC_CHECK_HEADERS(sys/select.h)


# Type checks.
AC_C_INLINE
AC_CHECK_SIZEOF(unsigned int)
AC_SYS_LARGEFILE
AC_TYPE_OFF_T

# Checks for compiler features.
if test "$GCC" = yes; then
    CFLAGS="$CFLAGS -Wall -Wcast-align -Wshadow -Wstrict-prototypes"
    if test "$have_w32_system" = yes; then
       CFLAGS="$CFLAGS -mms-bitfields"
    fi
fi

# Network library fun.
AC_CHECK_FUNC(gethostbyname, , AC_CHECK_LIB(nsl, gethostbyname,
	[NETLIBS="-lnsl $NETLIBS"]))
AC_CHECK_FUNC(setsockopt, , AC_CHECK_LIB(socket, setsockopt,
	[NETLIBS="-lsocket $NETLIBS"]))
AC_SUBST(NETLIBS)

# Checks for library functions.
AC_FUNC_FSEEKO

AC_REPLACE_FUNCS(vasprintf)
if test "$ac_cv_func_vasprintf" != yes; then
  GNUPG_CHECK_VA_COPY
fi

# Try to find a thread-safe version of ttyname().
AC_REPLACE_FUNCS(ttyname_r)
if test "$ac_cv_func_ttyname_r" != yes; then
  AC_MSG_WARN([
***
*** ttyname() is not thread-safe and ttyname_r() does not exist
***])
fi

# Try to find a thread-safe version of getenv().
have_thread_safe_getenv=no
jm_GLIBC21
if test $GLIBC21 = yes; then
  have_thread_safe_getenv=yes
fi
if test $have_thread_safe_getenv = yes; then
  AC_DEFINE(HAVE_THREAD_SAFE_GETENV, [1], [Define if getenv() is thread-safe])
fi
have_getenv_r=no
AC_CHECK_FUNCS(getenv_r, have_getenv_r=yes)
if test $have_getenv_r = no && test $have_thread_safe_getenv = no; then
  AC_MSG_WARN([
***
*** getenv() is not thread-safe and getenv_r() does not exist
***])
fi

# For converting time strings to seconds since Epoch, we need the timegm
# function.
AC_CHECK_FUNCS(timegm)
if test "$ac_cv_func_timegm" != yes; then
  AC_MSG_WARN([
***
*** timegm() not available - a non-thread-safe kludge will be used
*** and the TZ variable might be changed at runtime.
***])
fi

# Checking for libgpg-error.
AM_PATH_GPG_ERROR(1.4,, AC_MSG_ERROR([libgpg-error was not found]))
AC_DEFINE(GPG_ERR_SOURCE_DEFAULT, GPG_ERR_SOURCE_GPGME,
          [The default error source for GPGME.])



# Checks for system services
NEED_GPG_VERSION_DEFAULT=1.3.0
NEED_GPGSM_VERSION_DEFAULT=1.9.6
NEED_GPGCONF_VERSION_DEFAULT=2.0.4
NEED_GPG_VERSION="$NEED_GPG_VERSION_DEFAULT"
NEED_GPGSM_VERSION="$NEED_GPGSM_VERSION_DEFAULT"
NEED_GPGCONF_VERSION="$NEED_GPGCONF_VERSION_DEFAULT"
AC_ARG_WITH(gpg-version,
	    AC_HELP_STRING([--with-gpg-version=VER], [require GnuPG version VER]),
	    NEED_GPG_VERSION=$withval)
if test "$NEED_GPG_VERSION" = "yes"; then
  NEED_GPG_VERSION="$NEED_GPG_VERSION_DEFAULT"
fi
if test "$NEED_GPG_VERSION" = "no"; then
  NEED_GPG_VERSION=0.0.0
fi
AC_ARG_WITH(gpgsm-version,
	    AC_HELP_STRING([--with-gpgsm-version=VER], [require GPGSM version VER]),
	    NEED_GPGSM_VERSION=$withval)
if test "$NEED_GPGSM_VERSION" = "yes"; then
  NEED_GPGSM_VERSION="$NEED_GPGSM_VERSION_DEFAULT"
fi
if test "$NEED_GPGSM_VERSION" = "no"; then
  NEED_GPGSM_VERSION=0.0.0
fi
AC_ARG_WITH(gpgconf-version,
	    AC_HELP_STRING([--with-gpgconf-version=VER], [require GPGCONF version VER]),
	    NEED_GPGCONF_VERSION=$withval)
if test "$NEED_GPGCONF_VERSION" = "yes"; then
  NEED_GPGCONF_VERSION="$NEED_GPGCONF_VERSION_DEFAULT"
fi
if test "$NEED_GPGCONF_VERSION" = "no"; then
  NEED_GPGCONF_VERSION=0.0.0
fi

AC_DEFINE_UNQUOTED(NEED_GPG_VERSION, "$NEED_GPG_VERSION",
				     [Min. needed GnuPG version.])
AC_DEFINE_UNQUOTED(NEED_GPGSM_VERSION, "$NEED_GPGSM_VERSION",
				       [Min. needed GPGSM version.])
AC_DEFINE_UNQUOTED(NEED_GPGCONF_VERSION, "$NEED_GPGCONF_VERSION",
				         [Min. needed GPGCONF version.])


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
      AC_MSG_WARN([
***
*** Could not find GnuPG, install GnuPG or use --with-gpg=PATH to enable it
***])
    else
      AC_MSG_ERROR([
***
*** Can not determine path to GnuPG when cross-compiling, use --with-gpg=PATH
***])
    fi
  fi
else
  AC_DEFINE_UNQUOTED(GPG_PATH, "$GPG", [Path to the GnuPG binary.])
  AC_SUBST(GPG)
fi
dnl Check for GnuPG version requirement.
GPG_VERSION=unknown
ok=maybe
if test -z "$GPG" -o "x$GPG" = "xno"; then
  ok=no
else
  if test "$cross_compiling" = "yes"; then
    AC_MSG_WARN([GnuPG version can not be checked when cross compiling])
    ok=no
  else
    if test ! -x "$GPG"; then
      AC_MSG_WARN([GnuPG not executable, version check disabled])
      ok=no
    fi
  fi
fi
if test "$ok" = "maybe"; then
  AC_MSG_CHECKING(for GPG >= $NEED_GPG_VERSION)
  req_major=`echo $NEED_GPG_VERSION | \
             sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\1/'`
  req_minor=`echo $NEED_GPG_VERSION | \
	     sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\2/'`
  req_micro=`echo $NEED_GPG_VERSION | \
	     sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\3/'`
  GPG_VERSION=`$GPG --version | sed -n '1 s/[[^0-9]]*\(.*\)/\1/p'`
  major=`echo $GPG_VERSION | \
	 sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\1/'`
  minor=`echo $GPG_VERSION | \
	 sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\2/'`
  micro=`echo $GPG_VERSION | \
	 sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\3/'`

  if test "$major" -gt "$req_major"; then
    ok=yes
  else
    if test "$major" -eq "$req_major"; then
      if test "$minor" -gt "$req_minor"; then
        ok=yes
      else
        if test "$minor" -eq "$req_minor"; then
          if test "$micro" -ge "$req_micro"; then
            ok=yes
	  fi
        fi
      fi
    fi
  fi
  if test "$ok" = "yes"; then
    AC_MSG_RESULT(yes)
  else
    AC_MSG_RESULT(no)
    AC_MSG_WARN([GPG must be at least version $NEED_GPG_VERSION])
  fi
fi
run_gpg_test="$ok"
AC_ARG_ENABLE(gpg-test,
  AC_HELP_STRING([--disable-gpg-test], [disable GPG run test]),
         run_gpg_test=$enableval)
AM_CONDITIONAL(RUN_GPG_TESTS, test "$run_gpg_test" = "yes")
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
      AC_MSG_WARN([
***
*** Could not find GpgSM, install GpgSM or use --with-gpgsm=PATH to enable it
***])
    else
      AC_MSG_ERROR([
***
*** Can not determine path to GpgSM when cross-compiling, use --with-gpgsm=PATH
***])
    fi
  fi
else
  AC_DEFINE_UNQUOTED(GPGSM_PATH, "$GPGSM", [Path to the GPGSM binary.])
  AC_DEFINE(ENABLE_GPGSM,1,[Whether GPGSM support is enabled])
fi
AM_CONDITIONAL(HAVE_GPGSM, test "$GPGSM" != "no")


dnl Check for GPGSM version requirement.
GPGSM_VERSION=unknown
ok=maybe
if test -z "$GPGSM" -o "x$GPGSM" = "xno"; then
  ok=no
else
  if test "$cross_compiling" = "yes"; then
    AC_MSG_WARN([GPGSM version can not be checked when cross compiling])
    ok=no
  else
    if test ! -x "$GPGSM"; then
      AC_MSG_WARN([GPGSM not executable, version check disabled])
      ok=no
    fi
  fi
fi
if test "$ok" = "maybe"; then
  AC_MSG_CHECKING(for GPGSM >= $NEED_GPGSM_VERSION)
  req_major=`echo $NEED_GPGSM_VERSION | \
             sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\1/'`
  req_minor=`echo $NEED_GPGSM_VERSION | \
	     sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\2/'`
  req_micro=`echo $NEED_GPGSM_VERSION | \
	     sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\3/'`
  GPGSM_VERSION=`$GPGSM --version | sed -n '1 s/[[^0-9]]*\(.*\)/\1/p'`
  major=`echo $GPGSM_VERSION | \
	 sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\1/'`
  minor=`echo $GPGSM_VERSION | \
	 sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\2/'`
  micro=`echo $GPGSM_VERSION | \
	 sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\3/'`

  if test "$major" -gt "$req_major"; then
    ok=yes
  else
    if test "$major" -eq "$req_major"; then
      if test "$minor" -gt "$req_minor"; then
        ok=yes
      else
        if test "$minor" -eq "$req_minor"; then
          if test "$micro" -ge "$req_micro"; then
            ok=yes
	  fi
        fi
      fi
    fi
  fi
  if test "$ok" = "yes"; then
    AC_MSG_RESULT(yes)
  else
    AC_MSG_RESULT(no)
    AC_MSG_WARN([GPGSM must be at least version $NEED_GPGSM_VERSION])
  fi
fi
run_gpgsm_test="$ok"
AC_ARG_ENABLE(gpgsm-test,
  AC_HELP_STRING([--disable-gpgsm-test], [disable GPGSM run test]),
         run_gpgsm_test=$enableval)
AM_CONDITIONAL(RUN_GPGSM_TESTS, test "$run_gpgsm_test" = "yes")


NO_OVERRIDE=no
AC_ARG_WITH(gpgconf,
	    AC_HELP_STRING([--with-gpgconf=PATH],
                           [use gpgconf binary at PATH]),
	    GPGCONF=$withval, NO_OVERRIDE=yes)
if test "$NO_OVERRIDE" = "yes" || test "$GPGCONF" = "yes"; then
  GPGCONF=
  NO_OVERRIDE=yes
  if test "$cross_compiling" != "yes"; then
    AC_PATH_PROG(GPGCONF, gpgconf)
  fi
  if test -z "$GPGCONF"; then
    GPGCONF="$GPGCONF_DEFAULT"
  fi
fi
if test "$GPGCONF" = no; then
  if test "$NO_OVERRIDE" = "yes"; then
    if test "$cross_compiling" != "yes"; then
      AC_MSG_WARN([
***
*** Could not find gpgconf, install gpgconf or use --with-gpgconf=PATH to enable it
***])
    else
      AC_MSG_ERROR([
***
*** Can not determine path to gpgconf when cross-compiling, use --with-gpgconf=PATH
***])
    fi
  fi
else
  AC_DEFINE_UNQUOTED(GPGCONF_PATH, "$GPGCONF", [Path to the GPGCONF binary.])
  AC_DEFINE(ENABLE_GPGCONF,1,[Whether GPGCONF support is enabled])
fi
AM_CONDITIONAL(HAVE_GPGCONF, test "$GPGCONF" != "no")

dnl Check for GPGCONF version requirement.
GPGCONF_VERSION=unknown
ok=maybe
if test -z "$GPGCONF" -o "x$GPGCONF" = "xno"; then
  ok=no
else
  if test "$cross_compiling" = "yes"; then
    AC_MSG_WARN([GPGCONF version can not be checked when cross compiling])
    ok=no
  else
    if test ! -x "$GPGCONF"; then
      AC_MSG_WARN([GPGCONF not executable, version check disabled])
      ok=no
    fi
  fi
fi
if test "$ok" = "maybe"; then
  AC_MSG_CHECKING(for GPGCONF >= $NEED_GPGCONF_VERSION)
  req_major=`echo $NEED_GPGCONF_VERSION | \
             sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\1/'`
  req_minor=`echo $NEED_GPGCONF_VERSION | \
	     sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\2/'`
  req_micro=`echo $NEED_GPGCONF_VERSION | \
	     sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\3/'`
  GPGCONF_VERSION=`$GPGCONF --version | sed -n '1 s/[[^0-9]]*\(.*\)/\1/p'`
  major=`echo $GPGCONF_VERSION | \
	 sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\1/'`
  minor=`echo $GPGCONF_VERSION | \
	 sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\2/'`
  micro=`echo $GPGCONF_VERSION | \
	 sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\3/'`

  if test "$major" -gt "$req_major"; then
    ok=yes
  else
    if test "$major" -eq "$req_major"; then
      if test "$minor" -gt "$req_minor"; then
        ok=yes
      else
        if test "$minor" -eq "$req_minor"; then
          if test "$micro" -ge "$req_micro"; then
            ok=yes
	  fi
        fi
      fi
    fi
  fi
  if test "$ok" = "yes"; then
    AC_MSG_RESULT(yes)
  else
    AC_MSG_RESULT(no)
    AC_MSG_WARN([GPGCONF must be at least version $NEED_GPGCONF_VERSION])
  fi
fi
run_gpgconf_test="$ok"
AC_ARG_ENABLE(gpgconf-test,
  AC_HELP_STRING([--disable-gpgconf-test], [disable GPGCONF run test]),
         run_gpgconf_test=$enableval)
AM_CONDITIONAL(RUN_GPGCONF_TESTS, test "$run_gpgconf_test" = "yes")

# Only build if supported.
AM_CONDITIONAL(BUILD_GPGCONF, test "$GPGCONF" != "no")
if test "$GPGCONF" != "no"; then
  AC_DEFINE(HAVE_GPGCONF, 1,
            [Defined if we are building with gpgconf support.])
fi


# FIXME: Only build if supported.
AM_CONDITIONAL(BUILD_ASSUAN, test "$GPGSM" != "no")
if test "$GPGSM" != "no"; then
  AC_DEFINE(HAVE_ASSUAN_H, 1,
            [Defined if we are building with assuan support.])
fi

# Check for funopen
AC_CHECK_FUNCS(funopen)
if test $ac_cv_func_funopen != yes; then
    # No funopen but we can implement that in terms of fopencookie.
    AC_CHECK_FUNCS(fopencookie)
    if test $ac_cv_func_fopencookie = yes; then
        AC_REPLACE_FUNCS(funopen)
    else
        AC_MSG_WARN([
***
*** No implementation of fopencookie or funopen available
***])
    fi
fi

# More assuan replacement functions.
AC_REPLACE_FUNCS(isascii)
AC_REPLACE_FUNCS(putc_unlocked)
AC_REPLACE_FUNCS(memrchr)
AC_REPLACE_FUNCS(stpcpy)
# Check for unistd.h for setenv replacement function.
AC_CHECK_HEADERS(unistd.h)
AC_REPLACE_FUNCS(setenv)

# More assuan checks.
AC_CHECK_HEADERS([sys/uio.h])

# Assuan check for descriptor passing.
AC_CHECK_MEMBER(struct cmsghdr.cmsg_len,
                [supports_descriptor_passing=yes],
                [supports_descriptor_passing=no
                 AC_MSG_WARN([
***
*** Data structure for sending ancillary data missing.
*** Descriptor passing won't work.
***])],[
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#if HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif
#include <unistd.h>
       ])

AC_ARG_ENABLE(fd-passing,
  AC_HELP_STRING([--enable-fd-passing], [use FD passing if supported]),
  use_descriptor_passing=$enableval)

if test "$supports_descriptor_passing" != "yes"; then
  use_descriptor_passing=no
fi

if test "$use_descriptor_passing" = "yes"; then
AC_DEFINE(USE_DESCRIPTOR_PASSING,1,
          [Defined if descriptor passing is enabled and supported])
fi

AM_CONDITIONAL(USE_DESCRIPTOR_PASSING, test "$use_descriptor_passing" = "yes")

# Assuan check for the getsockopt SO_PEERCRED
AC_MSG_CHECKING(for SO_PEERCRED)
AC_CACHE_VAL(assuan_cv_sys_so_peercred,
      [AC_TRY_COMPILE([#include <sys/socket.h>], 
         [struct ucred cr; 
          int cl = sizeof cr;
          getsockopt (1, SOL_SOCKET, SO_PEERCRED, &cr, &cl);],
          assuan_cv_sys_so_peercred=yes,
          assuan_cv_sys_so_peercred=no)
       ])
AC_MSG_RESULT($assuan_cv_sys_so_peercred) 
if test $assuan_cv_sys_so_peercred = yes; then
  AC_DEFINE(HAVE_SO_PEERCRED, 1,
            [Defined if SO_PEERCRED is supported (Linux specific)])
fi

if test "$have_w32_system" = yes; then
   NETLIBS="-lws2_32 $NETLIBS"
fi

# End of assuan checks.

AM_CONDITIONAL(BUILD_COMPLUS, test "$component_system" = "COM+")

# Generate values for the DLL version info
if test "$have_w32_system" = yes; then
    BUILD_TIMESTAMP=`date --iso-8601=minutes`
    changequote(,)dnl 
    BUILD_FILEVERSION=`echo "$VERSION" | sed 's/\([0-9.]*\).*/\1./;s/\./,/g'`
    changequote([,])dnl
    BUILD_FILEVERSION="${BUILD_FILEVERSION}${BUILD_REVISION}"
fi
AC_SUBST(BUILD_REVISION)
AC_SUBST(BUILD_TIMESTAMP)
AC_SUBST(BUILD_FILEVERSION)

# Add a few constants to help porting to W32
AH_VERBATIM([SEPCONSTANTS],
[
/* Separators as used in $PATH.  */
#ifdef HAVE_DOSISH_SYSTEM
#define PATHSEP_C ';'
#else
#define PATHSEP_C ':'
#endif
])

AH_BOTTOM([
/* Definition of GCC specific attributes.  */
#if __GNUC__ > 2 
# define GPGME_GCC_A_PURE  __attribute__ ((__pure__))
#else
# define GPGME_GCC_A_PURE
#endif
])


# Substitution used for gpgme-config 
GPGME_CONFIG_LIBS="-lgpgme"
GPGME_CONFIG_CFLAGS=""
AC_SUBST(GPGME_CONFIG_API_VERSION)
AC_SUBST(GPGME_CONFIG_LIBS)
AC_SUBST(GPGME_CONFIG_CFLAGS)

# Frob'da Variables
LTLIBOBJS=`echo "$LIB@&t@OBJS" |
           sed 's,\.[[^.]]* ,.lo ,g;s,\.[[^.]]*$,.lo,'`
AC_SUBST(LTLIBOBJS)

#
# Create config files 

AC_CONFIG_FILES(Makefile assuan/Makefile src/Makefile
		tests/Makefile tests/gpg/Makefile tests/gpgsm/Makefile
		doc/Makefile complus/Makefile
                src/versioninfo.rc
                src/gpgme.h)
AC_CONFIG_FILES(src/gpgme-config, chmod +x src/gpgme-config)
AC_CONFIG_FILES([lang/Makefile lang/cl/Makefile lang/cl/gpgme.asd])
AC_OUTPUT

echo "
	GPGME v${VERSION} has been configured as follows:

	GnuPG path:      $GPG
        GnuPG version:   $GPG_VERSION, min. $NEED_GPG_VERSION

	GpgSM path:      $GPGSM
        GpgSM version:   $GPGSM_VERSION, min. $NEED_GPGSM_VERSION

	GpgConf path:    $GPGCONF
        GpgConf version: $GPGCONF_VERSION, min. $NEED_GPGCONF_VERSION

	GPGME Pthread:   $have_pthread
	GPGME Pth:       $have_pth
"
