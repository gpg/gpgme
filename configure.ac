# configure.ac for GPGME
# Copyright (C) 2000 Werner Koch (dd9jn)
# Copyright (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008,
#               2009, 2010, 2011, 2012  g10 Code GmbH
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
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.

# (Process this file with autoconf to produce a configure script.)
AC_PREREQ(2.59)
min_automake_version="1.11"

# Version number: Remember to change it immediately *after* a release.
#                 Make sure to run  "svn up" and "./autogen.sh --force"
#                 before a "make dist".  See below for the LT versions.
#                 Never do a binary build with the same version number
#                 in another year; this would mess up the build number.
#
# The GIT version is usually the next intended release version with
# the string "-gitNNNNNN" appended.  The reason for this is that tests
# for a specific feature can already be done under the assumption that
# the GIT version is the most recent one in a branch.  To disable the
# GIT version for the real release, set the my_isgit macro to no.
m4_define(my_version, [1.3.2])
m4_define(my_isgit, [no])

m4_define([svn_revision], m4_esyscmd([printf "%d" $( (svn info 2>/dev/null \
            || echo 'Revision: 0')|sed -n '/^Revision:/ {s/[^0-9]//gp;q;}')]))
m4_define([git_revision], m4_esyscmd([git branch -v 2>/dev/null \
          | awk '/^\* / {printf "%s",$3}']))
m4_define([my_full_version], [my_version[]m4_if(my_isgit,[yes],
          [m4_if(git_revision,[],[-svn[]svn_revision],[-git[]git_revision])])])

AC_INIT([gpgme],[my_full_version],[http://bugs.gnupg.org])

# LT Version numbers, remember to change them just *before* a release.
#   (Code changed:			REVISION++)
#   (Interfaces added/removed/changed:	CURRENT++, REVISION=0)
#   (Interfaces added:			AGE++)
#   (Interfaces removed/changed:	AGE=0)
#
LIBGPGME_LT_CURRENT=19
# Subtract 2 from this value if you want to make the LFS transition an
# ABI break.  [Note to self: Remove this comment with the next regular break.]
LIBGPGME_LT_AGE=8
LIBGPGME_LT_REVISION=1

# If the API is changed in an incompatible way: increment the next counter.
GPGME_CONFIG_API_VERSION=1
##############################################

NEED_LIBASSUAN_API=2
NEED_LIBASSUAN_VERSION=2.0.2


m4_define([git_brevis],m4_esyscmd(printf "%u" 0x[]m4_substr(git_revision,0,4)))
BUILD_REVISION=m4_if(git_revision,[],[svn_revision],[git_brevis])
PACKAGE=$PACKAGE_NAME
VERSION=$PACKAGE_VERSION

AC_CONFIG_SRCDIR(src/gpgme.h.in)
AM_CONFIG_HEADER(config.h)
AC_CONFIG_MACRO_DIR([m4])
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
AC_CHECK_PROGS(GITLOG_TO_CHANGELOG, gitlog-to-changelog,
               [build-aux/gitlog-to-changelog])

AC_SUBST(LIBGPGME_LT_CURRENT)
AC_SUBST(LIBGPGME_LT_AGE)
AC_SUBST(LIBGPGME_LT_REVISION)

AC_SUBST(PACKAGE)
AC_SUBST(VERSION)
AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE", [Name of this package])
AC_DEFINE_UNQUOTED(VERSION, "$VERSION", [Version of this package])

# Don't default to build static libs.
LT_PREREQ([2.2.6])
LT_INIT([win32-dll disable-static])
LT_LANG([Windows Resource])

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
G13_DEFAULT=no
component_system=None
have_dosish_system=no
have_w32_system=no
have_w64_system=no
build_w32_glib=no
build_w32_qt=no
case "${host}" in
    x86_64-*mingw32*)
        have_w64_system=yes
        ;;
    *-mingw32ce*)
        have_w32ce_system=yes
	;;
esac
case "${host}" in
    *-mingw32ce*|*-mingw32*)
	have_dosish_system=yes
        have_w32_system=yes
        GPG_DEFAULT='c:\\gnupg\\gpg.exe'
	GPGSM_DEFAULT='c:\\gnupg\\gpgsm.exe'
        GPGCONF_DEFAULT='c:\\gnupg\\gpgconf.exe'
        G13_DEFAULT='c:\\gnupg\\g13.exe'
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
	AC_CHECK_LIB(pthread,pthread_create,have_pthread=yes)
	if test "$have_pthread" = yes; then
	  AC_DEFINE(HAVE_PTHREAD, ,[Define if we have pthread.])
	fi

	# XXX: Probably use exec-prefix here?
#	GPG_DEFAULT='/usr/bin/gpg'
#	GPGSM_DEFAULT='/usr/bin/gpgsm'
#	GPGCONF_DEFAULT='/usr/bin/gpgconf'
#	G13_DEFAULT='/usr/bin/g13'
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
   AC_DEFINE(HAVE_W32_SYSTEM,1,
             [Defined if we run on any kind of W32 API based system])
fi
AM_CONDITIONAL(HAVE_W32_SYSTEM, test "$have_w32_system" = yes)

if test "$have_w64_system" = yes; then
   AC_DEFINE(HAVE_W64_SYSTEM,1,
             [Defined if we run on a 64 bit W32 API based system])
fi
AM_CONDITIONAL(HAVE_W64_SYSTEM, test "$have_w64_system" = yes)

if test "$have_w32ce_system" = yes; then
   AC_DEFINE(HAVE_W32CE_SYSTEM,1,
             [Defined if we run on a W32 CE API based system])
fi
AM_CONDITIONAL(HAVE_W32CE_SYSTEM, test "$have_w32ce_system" = yes)

AM_CONDITIONAL(BUILD_W32_GLIB, test "$build_w32_glib" = yes)
AM_CONDITIONAL(BUILD_W32_QT, test "$build_w32_qt" = yes)

AM_CONDITIONAL(HAVE_PTHREAD, test "$have_pthread" = "yes")



# Checks for header files.
AC_CHECK_HEADERS_ONCE([locale.h sys/select.h sys/uio.h argp.h
                       unistd.h sys/time.h sys/types.h sys/stat.h])


# Type checks.
AC_C_INLINE
AC_CHECK_SIZEOF(unsigned int)
AC_SYS_LARGEFILE
AC_TYPE_OFF_T
AC_TYPE_UINTPTR_T

# A simple compile time check in gpgme.h for GNU/Linux systems that
# prevents a file offset bits mismatch between gpgme and the application.
NEED__FILE_OFFSET_BITS=0
case "$ac_cv_sys_file_offset_bits" in
  "" | no | unknown) ;;
  *)
  NEED__FILE_OFFSET_BITS=$ac_cv_sys_file_offset_bits
  ;;
esac
AC_SUBST(NEED__FILE_OFFSET_BITS)

# Figure out platform dependent typedefs for gpgme.h
if test "$have_w32_system" = yes; then
   if test "$have_w64_system" = yes; then
      INSERT__TYPEDEFS_FOR_GPGME_H="/* Typedefs for the 64 bit W32 API.  */
#include <basetsd.h>
typedef long off_t;
typedef __int64 ssize_t;"
   else
      INSERT__TYPEDEFS_FOR_GPGME_H="/* Typedefs for the 32 bit W32 API.  */
typedef long off_t;
typedef long ssize_t;"
   fi
else
   INSERT__TYPEDEFS_FOR_GPGME_H="#include <sys/types.h>"
fi
AC_SUBST(INSERT__TYPEDEFS_FOR_GPGME_H)
AM_SUBST_NOTMAKE(INSERT__TYPEDEFS_FOR_GPGME_H)

# Checks for compiler features.
if test "$GCC" = yes; then
    CFLAGS="$CFLAGS -Wall -Wcast-align -Wshadow -Wstrict-prototypes"
    if test "$have_w32_system" = yes; then
       CFLAGS="$CFLAGS -mms-bitfields"
    fi
fi

# Only used for debugging, so no serious test needed (for actual
# functionality you have to test libc as well, this only tests the
# compiler).
AC_CACHE_CHECK([for __thread],[gpgme_cv_tls_works],
   AC_COMPILE_IFELSE([AC_LANG_PROGRAM([__thread int foo;])],
                     gpgme_cv_tls_works=yes,gpgme_cv_tls_works=no))
if test "$gpgme_cv_tls_works" = yes; then
  AC_DEFINE(HAVE_TLS, [1], [Define if __thread is supported])
fi


# Checks for library functions.
AC_FUNC_FSEEKO

AC_REPLACE_FUNCS(vasprintf)
if test "$ac_cv_func_vasprintf" != yes; then
  GNUPG_CHECK_VA_COPY
fi

# Try to find a thread-safe version of ttyname().
gnupg_REPLACE_TTYNAME_R
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

AC_CHECK_FUNCS(setlocale)

# Checking for libgpg-error.
AM_PATH_GPG_ERROR(1.8,, AC_MSG_ERROR([libgpg-error was not found]))
AC_DEFINE(GPG_ERR_SOURCE_DEFAULT, GPG_ERR_SOURCE_GPGME,
          [The default error source for GPGME.])

# And for libassuan.
have_libassuan=no
AM_PATH_LIBASSUAN("$NEED_LIBASSUAN_API:$NEED_LIBASSUAN_VERSION",
                  have_libassuan=yes, have_libassuan=no)
if test "$have_libassuan" = "yes"; then
  AC_DEFINE_UNQUOTED(GPGME_LIBASSUAN_VERSION, "$libassuan_version",
                     [version of the libassuan library])
fi
AM_CONDITIONAL(HAVE_ASSUAN, test "$have_libassuan" = "yes")
if test "$have_libassuan" = "yes"; then
  AC_DEFINE(ENABLE_ASSUAN,1,[Whether Assuan support is enabled])
fi

# Checks for system services
NEED_GPG_VERSION_DEFAULT=1.4.0
NEED_GPGSM_VERSION_DEFAULT=1.9.6
NEED_GPGCONF_VERSION_DEFAULT=2.0.4
NEED_G13_VERSION_DEFAULT=2.1.0
NEED_GPG_VERSION="$NEED_GPG_VERSION_DEFAULT"
NEED_GPGSM_VERSION="$NEED_GPGSM_VERSION_DEFAULT"
NEED_GPGCONF_VERSION="$NEED_GPGCONF_VERSION_DEFAULT"
NEED_G13_VERSION="$NEED_G13_VERSION_DEFAULT"
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
AC_ARG_WITH(g13-version,
	    AC_HELP_STRING([--with-g13-version=VER], [require G13 version VER]),
	    NEED_G13_VERSION=$withval)
if test "$NEED_G13_VERSION" = "yes"; then
  NEED_G13_VERSION="$NEED_G13_VERSION_DEFAULT"
fi
if test "$NEED_G13_VERSION" = "no"; then
  NEED_G13_VERSION=0.0.0
fi

AC_DEFINE_UNQUOTED(NEED_GPG_VERSION, "$NEED_GPG_VERSION",
				     [Min. needed GnuPG version.])
AC_DEFINE_UNQUOTED(NEED_GPGSM_VERSION, "$NEED_GPGSM_VERSION",
				       [Min. needed GPGSM version.])
AC_DEFINE_UNQUOTED(NEED_GPGCONF_VERSION, "$NEED_GPGCONF_VERSION",
				         [Min. needed GPGCONF version.])
AC_DEFINE_UNQUOTED(NEED_G13_VERSION, "$NEED_G13_VERSION",
				     [Min. needed G13 version.])


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


NO_OVERRIDE=no
AC_ARG_WITH(g13,
	    AC_HELP_STRING([--with-g13=PATH],
                           [use g13 binary at PATH]),
	    G13=$withval, NO_OVERRIDE=yes)
if test "$NO_OVERRIDE" = "yes" || test "$G13" = "yes"; then
  G13=
  NO_OVERRIDE=yes
  if test "$cross_compiling" != "yes"; then
    AC_PATH_PROG(G13, g13)
  fi
  if test -z "$G13"; then
    G13="$G13_DEFAULT"
  fi
fi
if test "$G13" = no; then
  if test "$NO_OVERRIDE" = "yes"; then
    if test "$cross_compiling" != "yes"; then
      AC_MSG_WARN([
***
*** Could not find g13, install g13 or use --with-g13=PATH to enable it
***])
    else
      AC_MSG_ERROR([
***
*** Can not determine path to g13 when cross-compiling, use --with-g13=PATH
***])
    fi
  fi
else
  AC_DEFINE_UNQUOTED(G13_PATH, "$G13", [Path to the G13 binary.])
  AC_DEFINE(ENABLE_G13,1,[Whether G13 support is enabled])
fi
AM_CONDITIONAL(HAVE_G13, test "$G13" != "no")

dnl Check for G13 version requirement.
G13_VERSION=unknown
ok=maybe
if test -z "$G13" -o "x$G13" = "xno"; then
  ok=no
else
  if test "$cross_compiling" = "yes"; then
    AC_MSG_WARN([G13 version can not be checked when cross compiling])
    ok=no
  else
    if test ! -x "$G13"; then
      AC_MSG_WARN([G13 not executable, version check disabled])
      ok=no
    fi
  fi
fi
if test "$ok" = "maybe"; then
  AC_MSG_CHECKING(for G13 >= $NEED_G13_VERSION)
  req_major=`echo $NEED_G13_VERSION | \
             sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\1/'`
  req_minor=`echo $NEED_G13_VERSION | \
	     sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\2/'`
  req_micro=`echo $NEED_G13_VERSION | \
	     sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\3/'`
  G13_VERSION=`$G13 --version | sed -n '1 s/.*\ \([[0-9]].*\)/\1/p'`
  major=`echo $G13_VERSION | \
	 sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\1/'`
  minor=`echo $G13_VERSION | \
	 sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\2/'`
  micro=`echo $G13_VERSION | \
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
    AC_MSG_WARN([G13 must be at least version $NEED_G13_VERSION])
  fi
fi
run_g13_test="$ok"
AC_ARG_ENABLE(g13-test,
  AC_HELP_STRING([--disable-g13-test], [disable G13 run test]),
         run_g13_test=$enableval)
AM_CONDITIONAL(RUN_G13_TESTS, test "$run_g13_test" = "yes")


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

# Check for getgid etc
AC_CHECK_FUNCS(getgid getegid)


# Replacement functions.
AC_REPLACE_FUNCS(stpcpy)
AC_REPLACE_FUNCS(setenv)

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

use_descriptor_passing=no
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


uiserver=no
if test "$use_descriptor_passing" = "yes" && test "$have_libassuan" = "yes"; then
  uiserver=yes
fi
if test "$uiserver" != "no"; then
  AC_DEFINE(ENABLE_UISERVER, 1,
            [Defined if we are building with uiserver support.])
fi
AM_CONDITIONAL(HAVE_UISERVER, test "$uiserver" != "no")


# Generate values for the DLL version info

dnl Windows uses an internal build number.  We use the last day of the
dnl year concatenated with the hour for it.  WARNING: You should not
dnl do a build with the same version number in another year.
if test "$have_w32_system" = yes; then
    BUILD_TIMESTAMP=`date --iso-8601=minutes`
    BUILD_NUMBER="$(date -u '+%j%H' | sed 's/^0*\(.*\)/\1/')"
    changequote(,)dnl
    BUILD_FILEVERSION=`echo "$VERSION" | sed 's/\([0-9.]*\).*/\1./;s/\./,/g'`
    changequote([,])dnl
    BUILD_FILEVERSION="${BUILD_FILEVERSION}${BUILD_NUMBER}"
fi
AC_SUBST(BUILD_NUMBER)
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

/* Under WindowsCE we need gpg-error's strerror macro.  */
#define GPG_ERR_ENABLE_ERRNO_MACROS 1
])


# Substitution used for gpgme-config
GPGME_CONFIG_LIBS="-lgpgme"
GPGME_CONFIG_CFLAGS=""
GPGME_CONFIG_HOST="$host"
AC_SUBST(GPGME_CONFIG_API_VERSION)
AC_SUBST(GPGME_CONFIG_LIBS)
AC_SUBST(GPGME_CONFIG_CFLAGS)
AC_SUBST(GPGME_CONFIG_HOST)

# Frob'da Variables
LTLIBOBJS=`echo "$LIB@&t@OBJS" |
           sed 's,\.[[^.]]* ,.lo ,g;s,\.[[^.]]*$,.lo,'`
AC_SUBST(LTLIBOBJS)

# Some checks for gpgme-tool
# Done at top: AC_CHECK_HEADER([argp.h])
AC_CHECK_TYPES([error_t], [],
   [AC_DEFINE([error_t], [int],
   [Define to a type to use for `error_t' if it is not otherwise available.])],
   [#include <errno.h>])


# A substitution to set generated files in a Emacs buffer to read-only.
AC_SUBST(emacs_local_vars_begin, ['Local Variables:'])
AC_SUBST(emacs_local_vars_read_only, ['buffer-read-only: t'])
AC_SUBST(emacs_local_vars_end, ['End:'])


# Last check.
die=no
if test "$have_libassuan" = "no"; then
   die=yes
   AC_MSG_NOTICE([[
***
*** You need libassuan to build this program with GPGSM support.
*** This library is for example available at
***   ftp://ftp.gnupg.org/gcrypt/libassuan/
*** (at least version $NEED_LIBASSUAN_VERSION (API $NEED_LIBASSUAN_API) is required).
***]])
fi

if test "$die" = "yes"; then
    AC_MSG_ERROR([[
***
*** Required libraries not found. Please consult the above messages
*** and install them before running configure again.
***]])
fi


#
# Create config files

AC_CONFIG_FILES(Makefile src/Makefile
		tests/Makefile
                tests/gpg/Makefile
                tests/gpgsm/Makefile
                tests/opassuan/Makefile
		doc/Makefile
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

        G13 path:        $G13
        G13 version:     $G13_VERSION, min. $NEED_G13_VERSION

        Assuan version:  $libassuan_version, min. $NEED_LIBASSUAN_VERSION

        UI Server:       $uiserver
        FD Passing:      $use_descriptor_passing

        GPGME Pthread:   $have_pthread
"
