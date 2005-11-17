# configure.ac for GPGME
# Copyright (C) 2000 Werner Koch (dd9jn)
# Copyright (C) 2001, 2002, 2003, 2004, 2005 g10 Code GmbH
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
min_automake_version="1.9.3"

# Version number: Remember to change it immediately *after* a release.
#                 Make sure to run  "svn up" before a "make dist".
AC_INIT(gpgme, 1.2.0-cvs, [bug-gpgme@gnupg.org])
# LT Version numbers, remember to change them just *before* a release.
#   (Code changed:			REVISION++)
#   (Interfaces added/removed/changed:	CURRENT++, REVISION=0)
#   (Interfaces added:			AGE++)
#   (Interfaces removed/changed:	AGE=0)
#
LIBGPGME_LT_CURRENT=16
# Subtract 2 from this value if you want to make the LFS transition an
# ABI break.  [Note to self: Remove this comment with the next regular break.]
LIBGPGME_LT_AGE=5
LIBGPGME_LT_REVISION=0

# If the API is changed in an incompatible way: increment the next counter.
GPGME_CONFIG_API_VERSION=1

NEED_GPG_VERSION=1.2.2
NEED_GPGSM_VERSION=1.9.6
##############################################


PACKAGE=$PACKAGE_NAME
VERSION=$PACKAGE_VERSION

AC_CONFIG_SRCDIR(gpgme/gpgme.h)
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
esac
AM_CONDITIONAL(HAVE_LD_VERSION_SCRIPT, test "$have_ld_version_script" = "yes")

GPG_DEFAULT=no
GPGSM_DEFAULT=no
component_system=None
have_dosish_system=no
have_w32_system=no
case "${host}" in
    *-mingw32*)
        # special stuff for Windoze NT
	have_dosish_system=yes
        have_w32_system=yes
        GPG_DEFAULT='c:\\gnupg\\gpg.exe'
	# XXX Assuan is not supported in this configuration.
	#GPGSM_DEFAULT='c:\\gnupg\\gpgsm.exe'
        #component_system='COM+'
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

build_w32_glib=no
AM_PATH_GLIB_2_0
AC_ARG_ENABLE(w32-glib,
	    AC_HELP_STRING([--enable-w32-glib], [build GPGME Glib for W32]),
	    build_w32_glib=$withval)
AM_CONDITIONAL(BUILD_W32_GLIB, test "$build_w32_glib" = yes)

AM_CONDITIONAL(HAVE_PTH, test "$have_pth" = "yes")
AM_CONDITIONAL(HAVE_PTHREAD, test "$have_pthread" = "yes")


# Checks for header files.
AC_CHECK_HEADERS(sys/select.h)


# Type checks.
AC_CHECK_SIZEOF(unsigned int)
AC_SYS_LARGEFILE
AC_TYPE_OFF_T

# Checks for compiler features.
if test "$GCC" = yes; then
    CFLAGS="$CFLAGS -Wall -Wcast-align -Wshadow -Wstrict-prototypes"
fi


# Checks for library functions.
AC_FUNC_FSEEKO

AC_CHECK_FUNCS(stpcpy)

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
AM_PATH_GPG_ERROR(0.5,, AC_MSG_ERROR([libgpg-error was not found]))
AC_DEFINE(GPG_ERR_SOURCE_DEFAULT, GPG_ERR_SOURCE_GPGME,
          [The default error source for GPGME.])



# Checks for system services
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
  AC_MSG_CHECKING(for GnuPG >= $NEED_GPG_VERSION)
  req_major=`echo $NEED_GPG_VERSION | \
             sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\1/'`
  req_minor=`echo $NEED_GPG_VERSION | \
	     sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\2/'`
  req_micro=`echo $NEED_GPG_VERSION | \
	     sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\3/'`
  gpg_version=`$GPG --version | grep ^gpg`
  major=`echo $gpg_version | \
	 sed 's/^gpg (GnuPG) \([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\1/'`
  minor=`echo $gpg_version | \
	 sed 's/^gpg (GnuPG) \([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\2/'`
  micro=`echo $gpg_version | \
	 sed 's/^gpg (GnuPG) \([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\3/'`
  GPG_VERSION=`echo $gpg_version | sed 's/^gpg (GnuPG) //'`

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
    AC_MSG_WARN([GnuPG must be at least version $NEED_GPG_VERSION])
  fi
fi
AM_CONDITIONAL(RUN_GPG_TESTS, test "$ok" = "yes")
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
  gpgsm_version=`$GPGSM --version | grep ^gpgsm`
  major=`echo $gpgsm_version | \
	 sed 's/^gpgsm (GnuPG) \([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\1/'`
  minor=`echo $gpgsm_version | \
	 sed 's/^gpgsm (GnuPG) \([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\2/'`
  micro=`echo $gpgsm_version | \
	 sed 's/^gpgsm (GnuPG) \([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\3/'`
  GPGSM_VERSION=`echo $gpgsm_version | sed 's/^gpgsm (GnuPG) //'`

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
AM_CONDITIONAL(RUN_GPGSM_TESTS, test "$ok" = "yes")

# FIXME: Only build if supported.
AM_CONDITIONAL(BUILD_ASSUAN, test "$GPGSM" != "no")


# The assuan code uses funopen but it will also build without it.  So
# test for it.  Frankly, this is not required in gpgme, but thats the
# way we handle it in libassuan.
AC_CHECK_FUNCS(funopen)
if test $ac_cv_func_funopen != yes; then
    # No funopen but we can implement that in terms of fopencookie.
    AC_CHECK_FUNCS(fopencookie)
    if test $ac_cv_func_fopencookie = yes; then
        AC_LIBOBJ([funopen])
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

# More assuan checks.
AC_CHECK_HEADERS([sys/uio.h])

# End of assuan checks.

AM_CONDITIONAL(BUILD_COMPLUS, test "$component_system" = "COM+")

# Make the version number in gpgme/gpgme.h the same as the one here.
# (this is easier than to have a *.in file just for one substitution)
GNUPG_FIX_HDR_VERSION(gpgme/gpgme.h, GPGME_VERSION)

# Generate values for the DLL version info
if test "$have_w32_system" = yes; then
    BUILD_TIMESTAMP=`date --iso-8601=minutes`
    changequote(,)dnl 
    BUILD_FILEVERSION=`echo "$VERSION" | sed 's/\([0-9.]*\).*/\1./;s/\./,/g'`
    tmp="`echo '$Revision$' | sed 's/[^0-9]//g'`"
    changequote([,])dnl
    test -z "$tmp" && tmp="0"
    BUILD_FILEVERSION="${BUILD_FILEVERSION}$tmp"
fi
AC_SUBST(BUILD_TIMESTAMP)
AC_SUBST(BUILD_FILEVERSION)

# Add a few constants to help porting to W32
AH_VERBATIM([SEPCONSTANTS],
[
/* Separators as used in file names and $PATH. Please note that the
   string version must not contain more than one character because
   the using code assumes strlen()==1 */
#ifdef HAVE_DOSISH_SYSTEM
#define DIRSEP_C '\\\\'
#define EXTSEP_C '.'
#define DIRSEP_S "\\\\"
#define EXTSEP_S "."
#define PATHSEP_C ';'
#define PATHSEP_S ";"
#else
#define DIRSEP_C '/'
#define EXTSEP_C '.'
#define DIRSEP_S "/"
#define EXTSEP_S "."
#define PATHSEP_C ':'
#define PATHSEP_S ":"
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

AC_CONFIG_FILES(Makefile assuan/Makefile gpgme/Makefile
		tests/Makefile tests/gpg/Makefile tests/gpgsm/Makefile
		doc/Makefile complus/Makefile
                gpgme/versioninfo.rc)
AC_CONFIG_FILES(gpgme/gpgme-config, chmod +x gpgme/gpgme-config)
AC_OUTPUT

echo "
	GPGME v${VERSION} has been configured as follows:

	GnuPG path:    $GPG
        GnuPG version: $GPG_VERSION, min. $NEED_GPG_VERSION

	GpgSM path:    $GPGSM
        GpgSM version: $GPGSM_VERSION, min. $NEED_GPGSM_VERSION

	GPGME Pthread: $have_pthread
	GPGME Pth:     $have_pth
"
