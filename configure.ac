# configure.ac for GPGME
# Copyright (C) 2000 Werner Koch (dd9jn)
# Copyright (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008,
#               2009, 2010, 2011, 2012, 2013, 2014, 2015  g10 Code GmbH
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
min_automake_version="1.14"

# To build a release you need to create a tag with the version number
# (git tag -s gpgme-n.m.k) and run "./autogen.sh --force".  Please
# bump the version number immediately after the release and do another
# commit and push so that the git magic is able to work.  See below
# for the LT versions.
m4_define(mym4_version_major, [1])
m4_define(mym4_version_minor, [7])
m4_define(mym4_version_micro, [0])

# Below is m4 magic to extract and compute the revision number, the
# decimalized short revision number, a beta version string, and a flag
# indicating a development version (mym4_isgit). Note that the m4
# processing is done by autoconf and not during the configure run.
m4_define(mym4_version,
          [mym4_version_major.mym4_version_minor.mym4_version_micro])
m4_define([mym4_revision],
          m4_esyscmd([git rev-parse --short HEAD | tr -d '\n\r']))
m4_define([mym4_revision_dec],
          m4_esyscmd_s([echo $((0x$(echo ]mym4_revision[|head -c 4)))]))
m4_define([mym4_betastring],
          m4_esyscmd_s([git describe --match 'gpgme-[0-9].*[0-9]' --long|\
                        awk -F- '$3!=0{print"-beta"$3}']))
m4_define([mym4_isgit],m4_if(mym4_betastring,[],[no],[yes]))
m4_define([mym4_full_version],[mym4_version[]mym4_betastring])

AC_INIT([gpgme],[mym4_full_version],[http://bugs.gnupg.org])

# LT Version numbers, remember to change them just *before* a release.
#   (Code changed:			REVISION++)
#   (Interfaces added/removed/changed:	CURRENT++, REVISION=0)
#   (Interfaces added:			AGE++)
#   (Interfaces removed/changed:	AGE=0)
#
LIBGPGME_LT_CURRENT=26
# Subtract 2 from this value if you want to make the LFS transition an
# ABI break.  [Note to self: Remove this comment with the next regular break.]
LIBGPGME_LT_AGE=15
LIBGPGME_LT_REVISION=0

LIBGPGMEPP_LT_CURRENT=6
LIBGPGMEPP_LT_AGE=0
LIBGPGMEPP_LT_REVISION=1

LIBQGPGME_LT_CURRENT=6
LIBQGPGME_LT_AGE=0
LIBQGPGME_LT_REVISION=1

# If the API is changed in an incompatible way: increment the next counter.
GPGME_CONFIG_API_VERSION=1
##############################################

NEED_GPG_ERROR_VERSION=1.11
NEED_LIBASSUAN_API=2
NEED_LIBASSUAN_VERSION=2.0.2


PACKAGE=$PACKAGE_NAME
VERSION=$PACKAGE_VERSION

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR(src/gpgme.h.in)
AC_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE([serial-tests dist-bzip2 no-dist-gzip])
AM_MAINTAINER_MODE
AC_CANONICAL_HOST
AM_SILENT_RULES
AC_ARG_VAR(SYSROOT,[locate config scripts also below that directory])

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

# Note: A suitable gitlog-to-changelog script can be found in GnuPG master.
AC_CHECK_PROGS(GITLOG_TO_CHANGELOG, gitlog-to-changelog, [gitlog-to-changelog])

AC_SUBST(LIBGPGME_LT_CURRENT)
AC_SUBST(LIBGPGME_LT_AGE)
AC_SUBST(LIBGPGME_LT_REVISION)
AC_SUBST(LIBGPGMEPP_LT_CURRENT)
AC_SUBST(LIBGPGMEPP_LT_AGE)
AC_SUBST(LIBGPGMEPP_LT_REVISION)
AC_SUBST(LIBQGPGME_LT_CURRENT)
AC_SUBST(LIBQGPGME_LT_AGE)
AC_SUBST(LIBQGPGME_LT_REVISION)

AC_SUBST(PACKAGE)
AC_SUBST(VERSION)
AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE", [Name of this package])
AC_DEFINE_UNQUOTED(VERSION, "$VERSION", [Version of this package])
VERSION_NUMBER=m4_esyscmd(printf "0x%02x%02x%02x" mym4_version_major \
                          mym4_version_minor mym4_version_micro)
AC_SUBST(VERSION_NUMBER)

# We need to compile and run a program on the build machine.  A
# comment in libgpg-error says that the AC_PROG_CC_FOR_BUILD macro in
# the AC archive is broken for autoconf 2.57.  Given that there is no
# newer version of that macro, we assume that it is also broken for
# autoconf 2.61 and thus we use a simple but usually sufficient
# approach.
AC_MSG_CHECKING(for cc for build)
if test "$cross_compiling" = "yes"; then
  CC_FOR_BUILD="${CC_FOR_BUILD-cc}"
else
  CC_FOR_BUILD="${CC_FOR_BUILD-$CC}"
fi
AC_MSG_RESULT($CC_FOR_BUILD)
AC_ARG_VAR(CC_FOR_BUILD,[build system C compiler])


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
have_android_system=no
have_w32_system=no
have_w64_system=no
build_w32_glib=no
build_w32_qt=no
available_languages="cl cpp python python2 python3 qt"
default_languages="cl cpp python qt"
case "${host}" in
    x86_64-*mingw32*)
        have_w64_system=yes
        ;;
    *-mingw32ce*)
        have_w32ce_system=yes
	;;
    *-linux-androideabi)
        have_android_system=yes
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

if test "$have_android_system" = yes; then
   AC_DEFINE(HAVE_ANDROID_SYSTEM,1, [Defined if we build for an Android system])
fi
AM_CONDITIONAL(HAVE_ANDROID_SYSTEM, test "$have_android_system" = yes)

AM_CONDITIONAL(BUILD_W32_GLIB, test "$build_w32_glib" = yes)

AM_CONDITIONAL(HAVE_PTHREAD, test "$have_pthread" = "yes")


AC_ARG_ENABLE([fixed-path],
              AC_HELP_STRING([--enable-fixed-path=PATH],
                             [locate binaries only via this PATH]),
              [fixed_search_path="$enableval"],
              [fixed_search_path=""])
if test x$fixed_search_path != x ; then
  AC_DEFINE_UNQUOTED(FIXED_SEARCH_PATH, "$fixed_search_path",
                    [Locate binaries only via this PATH])
fi


# Note: You need to declare all possible langauges also in
#       lang/Makefile.am's DIST_SUBDIRS.
AC_ARG_ENABLE([languages],
              AC_HELP_STRING([--enable-languages=languages],
                             [enable only specific language bindings]),
                             [enabled_languages=`echo $enableval | \
                             tr ',:' '  ' | tr '[A-Z]' '[a-z]' | \
                             sed 's/c++/cpp/'`],
                             [enabled_languages="maybe"])
if test "x$enabled_languages" = "x" \
   -o "$enabled_languages" = "no"; then
   enabled_languages=
fi

# If languages are explicitly set missing requirements
# for the languages are treated as errors otherwise
# there will be a warning.
explicit_languages=1
if test "x$enabled_languages" = "xmaybe"; then
    explicit_languages=0
    enabled_languages="$default_languages"
fi

for language in $enabled_languages; do
    LIST_MEMBER($language, $available_languages)
    if test "$found" = "0"; then
       AC_MSG_ERROR([unsupported language binding specified])
    fi
done



# Enable C++ 11 if cpp language is requested
LIST_MEMBER("cpp", $enabled_languages)
if test "$found" = "1"; then
    AX_CXX_COMPILE_STDCXX(11, noext, optional)
    if test "$HAVE_CXX11" != "1"; then
        if test "$explicit_languages" = "1"; then
            AC_MSG_ERROR([[
***
*** A compiler with c++11 support is required for the c++ binding.
***]])
        else
            enabled_languages=$(echo $enabled_languages | sed 's/cpp//')
            enabled_languages=$(echo $enabled_languages | sed 's/qt//')
            AC_MSG_WARN([[
***
*** No c++11 support detected. C++ and Qt bindings will be disabled.
***]])
        fi
    fi
fi

# Check that if qt is enabled cpp also is enabled
LIST_MEMBER("qt", $enabled_languages)
if test "$found" = "1"; then
    # We need to ensure that in the langauge order qt comes after cpp
    # so we remove qt first and explicitly add it as last list member.
    enabled_languages=$(echo $enabled_languages | sed 's/qt//')
    LIST_MEMBER("cpp", $enabled_languages)
    if test "$found" = "0"; then
        AC_MSG_ERROR([[
***
*** Qt language binding depends on cpp binding.
***]])
    fi
    FIND_QT
    if test "$have_qt5_libs" != "yes"; then
        if test "$explicit_languages" = "1"; then
        AC_MSG_ERROR([[
***
*** Qt5 (Qt5Core) is required for Qt binding.
***]])
        else
           AC_MSG_WARN([[
***
*** Qt5 (Qt5Core) not found Qt Binding will be disabled.
***]])
        fi
    else
        enabled_languages=`echo $enabled_languages qt`

        AC_CHECK_PROGS([DOXYGEN], [doxygen])
        if test -z "$DOXYGEN";
            # This is not highlighted becase it's not really important.
            then AC_MSG_WARN([Doxygen not found - Qt binding doc will not be built.])
        fi
        AC_CHECK_PROGS([GRAPHVIZ], [dot])
        if test -z "$GRAPHVIZ";
            then AC_MSG_WARN([Graphviz not found - Qt binding doc will not have diagrams.])
        fi
    fi
fi
AM_CONDITIONAL([HAVE_DOXYGEN],
               [test -n "$DOXYGEN"])
if test -n "$GRAPHVIZ"; then
    HAVE_DOT="YES"
else
    HAVE_DOT="NO"
fi
AC_SUBST(HAVE_DOT)

# Python bindings.
LIST_MEMBER("python2", $enabled_languages)
found_py2=$found
LIST_MEMBER("python3", $enabled_languages)
found_py3=$found
LIST_MEMBER("python", $enabled_languages)
found_py=$found
if test "$found_py" = "1" -o "$found_py2" = "1" -o "$found_py3" = "1"; then
    AX_PKG_SWIG
    if test -z "$SWIG"; then
        if test "$explicit_languages" = "1"; then
            AC_MSG_ERROR([[
***
*** You need SWIG to build the Python bindings.
***]])
        else
            enabled_languages=$(echo $enabled_languages | sed 's/python//')
        fi
    else
        # Reset all the stuff, just to be sure.
	PYTHONS=
	PYTHON_VERSIONS=
	unset PYTHON
	unset PYTHON_VERSION
	unset PYTHON_CPPFLAGS
	unset PYTHON_LDFLAGS
	unset PYTHON_SITE_PKG
	unset PYTHON_EXTRA_LIBS
	unset PYTHON_EXTRA_LDFLAGS
	unset ac_cv_path_PYTHON
	unset am_cv_pathless_PYTHON
	unset am_cv_python_version
	unset am_cv_python_platform
	unset am_cv_python_pythondir
	unset am_cv_python_pyexecdir

	if test "$found_py" = "1" -o "$found_py2" = "1"; then
	    AM_PATH_PYTHON([2.7])
	    AX_PYTHON_DEVEL
	    if test "$PYTHON_VERSION"; then
		PYTHONS="$(echo $PYTHONS $PYTHON)"
		PYTHON_VERSIONS="$(echo $PYTHON_VERSIONS $PYTHON_VERSION)"
	    fi
	fi

	if test "$found_py" = "1" -o "$found_py3" = "1"; then
	    # Reset everything, so that we can look for another Python.
	    unset PYTHON
	    unset PYTHON_VERSION
	    unset PYTHON_CPPFLAGS
	    unset PYTHON_LDFLAGS
	    unset PYTHON_SITE_PKG
	    unset PYTHON_EXTRA_LIBS
	    unset PYTHON_EXTRA_LDFLAGS
	    unset ac_cv_path_PYTHON
	    unset am_cv_pathless_PYTHON
	    unset am_cv_python_version
	    unset am_cv_python_platform
	    unset am_cv_python_pythondir
	    unset am_cv_python_pyexecdir
	    AM_PATH_PYTHON([3.4])
	    AX_PYTHON_DEVEL
	    if test "$PYTHON_VERSION"; then
		PYTHONS="$(echo $PYTHONS $PYTHON)"
		PYTHON_VERSIONS="$(echo $PYTHON_VERSIONS $PYTHON_VERSION)"
	    fi
	fi

	if test "$PYTHON_VERSIONS"; then
	   enabled_languages_v=$(echo $enabled_languages | sed "s/python\([[23]]\)\?/python ($PYTHON_VERSIONS)/")
	   enabled_languages=$(echo $enabled_languages | sed "s/python\([[23]]\)\?/python/")
	else
            if test "$explicit_languages" = "1"; then
                AC_MSG_ERROR([[
***
*** Please install the python development packages.
***]])
	    else
                enabled_languages=$(echo $enabled_languages | sed 's/python//')
            fi
	fi

	AC_SUBST(PYTHONS, $PYTHONS)
	AC_SUBST(PYTHON_VERSIONS, $PYTHON_VERSIONS)
    fi
fi

AC_SUBST(ENABLED_LANGUAGES, $enabled_languages)

#
# Provide information about the build.
#
BUILD_REVISION="mym4_revision"
AC_SUBST(BUILD_REVISION)
AC_DEFINE_UNQUOTED(BUILD_REVISION, "$BUILD_REVISION",
                   [GIT commit id revision used to build this package])

changequote(,)dnl
BUILD_FILEVERSION=`echo "$PACKAGE_VERSION"|sed 's/\([0-9.]*\).*/\1./;s/\./,/g'`
changequote([,])dnl
BUILD_FILEVERSION="${BUILD_FILEVERSION}mym4_revision_dec"
AC_SUBST(BUILD_FILEVERSION)

AC_ARG_ENABLE([build-timestamp],
  AC_HELP_STRING([--enable-build-timestamp],
                 [set an explicit build timestamp for reproducibility.
                  (default is the current time in ISO-8601 format)]),
     [if test "$enableval" = "yes"; then
        BUILD_TIMESTAMP=`date -u +%Y-%m-%dT%H:%M+0000 2>/dev/null || date`
      else
        BUILD_TIMESTAMP="$enableval"
      fi],
     [BUILD_TIMESTAMP="<none>"])
AC_SUBST(BUILD_TIMESTAMP)
AC_DEFINE_UNQUOTED(BUILD_TIMESTAMP, "$BUILD_TIMESTAMP",
                   [The time this package was configured for a build])


#
# Options to disable some regression tests
#
run_gpgconf_test="yes"
AC_ARG_ENABLE(gpgconf-test,
  AC_HELP_STRING([--disable-gpgconf-test], [disable GPGCONF regression test]),
         run_gpgconf_test=$enableval)
AM_CONDITIONAL(RUN_GPGCONF_TESTS, test "$run_gpgconf_test" = "yes")

run_gpg_test="yes"
AC_ARG_ENABLE(gpg-test,
  AC_HELP_STRING([--disable-gpg-test], [disable GPG regression test]),
         run_gpg_test=$enableval)
AM_CONDITIONAL(RUN_GPG_TESTS, test "$run_gpg_test" = "yes")

run_gpgsm_test="yes"
AC_ARG_ENABLE(gpgsm-test,
  AC_HELP_STRING([--disable-gpgsm-test], [disable GPGSM regression test]),
         run_gpgsm_test=$enableval)
AM_CONDITIONAL(RUN_GPGSM_TESTS, test "$run_gpgsm_test" = "yes")

run_g13_test="yes"
AC_ARG_ENABLE(g13-test,
  AC_HELP_STRING([--disable-g13-test], [disable G13 regression test]),
         run_g13_test=$enableval)
AM_CONDITIONAL(RUN_G13_TESTS, test "$run_g13_test" = "yes")


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
if test "$have_w32_system" != yes; then
  case "$ac_cv_sys_file_offset_bits" in
    "" | no | unknown) ;;
    *)
    NEED__FILE_OFFSET_BITS=$ac_cv_sys_file_offset_bits
    ;;
  esac
fi
AC_SUBST(NEED__FILE_OFFSET_BITS)

# Figure out platform dependent typedefs for gpgme.h
if test "$have_w32_system" = yes; then
    INSERT__TYPEDEFS_FOR_GPGME_H="
#ifdef _WIN64
# include <stdint.h>
  typedef int64_t gpgme_off_t;
  typedef int64_t gpgme_ssize_t;
#else /* _WIN32 */
  typedef long gpgme_off_t;
  typedef long gpgme_ssize_t;
#endif /* _WIN32 */"
    API__OFF_T="gpgme_off_t"
    API__SSIZE_T="gpgme_ssize_t"
else
    INSERT__TYPEDEFS_FOR_GPGME_H="
#include <sys/types.h>
typedef off_t   gpgme_off_t;
typedef ssize_t gpgme_ssize_t;"
    API__OFF_T="off_t"
    API__SSIZE_T="ssize_t"
fi
AC_SUBST(INSERT__TYPEDEFS_FOR_GPGME_H)
AM_SUBST_NOTMAKE(INSERT__TYPEDEFS_FOR_GPGME_H)
AC_SUBST(API__OFF_T)
AM_SUBST_NOTMAKE(API__OFF_T)
AC_SUBST(API__SSIZE_T)
AM_SUBST_NOTMAKE(API__SSIZE_T)

# Checks for compiler features.
if test "$GCC" = yes; then
    CFLAGS="$CFLAGS -Wall -Wcast-align -Wshadow -Wstrict-prototypes"
    if test "$USE_MAINTAINER_MODE" = "yes"; then
        CFLAGS="$CFLAGS -Wformat -Wno-format-y2k -Wformat-security"

        # If -Wno-missing-field-initializers is supported we can enable a
        # a bunch of really useful warnings.
        AC_MSG_CHECKING([if gcc supports -Wno-missing-field-initializers])
        _gcc_cflags_save=$CFLAGS
        CFLAGS="-Wno-missing-field-initializers"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],_gcc_wopt=yes,_gcc_wopt=no)
        AC_MSG_RESULT($_gcc_wopt)
        CFLAGS=$_gcc_cflags_save;
        if test x"$_gcc_wopt" = xyes ; then
          CFLAGS="$CFLAGS -W -Wextra -Wbad-function-cast"
          CFLAGS="$CFLAGS -Wwrite-strings"
          CFLAGS="$CFLAGS -Wdeclaration-after-statement"
          CFLAGS="$CFLAGS -Wno-missing-field-initializers"
          CFLAGS="$CFLAGS -Wno-sign-compare"
        fi

        AC_MSG_CHECKING([if gcc supports -Wpointer-arith])
        _gcc_cflags_save=$CFLAGS
        CFLAGS="-Wpointer-arith"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],_gcc_wopt=yes,_gcc_wopt=no)
        AC_MSG_RESULT($_gcc_wopt)
        CFLAGS=$_gcc_cflags_save;
        if test x"$_gcc_wopt" = xyes ; then
          CFLAGS="$CFLAGS -Wpointer-arith"
        fi
    fi
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
AC_MSG_NOTICE([checking for libraries])

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
have_gpg_error=no
AM_PATH_GPG_ERROR("$NEED_GPG_ERROR_VERSION",
                  have_gpg_error=yes, have_gpg_error=no)
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


#
# Other checks
#

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


dnl There seems to be a problem with Apple and decriptor passing.
dnl Until we found a solution we change the default to no.
dnl See bug 1483.
case "${host}" in
    *-apple-darwin*)
      use_descriptor_passing=no
      ;;
    *)
      use_descriptor_passing=yes
      ;;
esac
AC_ARG_ENABLE(fd-passing,
  AC_HELP_STRING([--disable-fd-passing], [do not use FD passing]),
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


# Add a few constants to help porting to W32
AH_VERBATIM([SEPCONSTANTS],
[
/* Separators as used in $PATH and file name.  */
#ifdef HAVE_DOSISH_SYSTEM
#define PATHSEP_C ';'
#define DIRSEP_C '\\'
#define DIRSEP_S "\\"
#else
#define PATHSEP_C ':'
#define DIRSEP_C '/'
#define DIRSEP_S "/"
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

#define CRIGHTBLURB "Copyright (C) 2000 Werner Koch\n" \
                    "Copyright (C) 2001--2016 g10 Code GmbH\n"
])


# Substitution used for gpgme-config
GPGME_CONFIG_LIBS="-lgpgme"
GPGME_CONFIG_CFLAGS=""
GPGME_CONFIG_HOST="$host"
GPGME_CONFIG_AVAIL_LANG="$enabled_languages"
AC_SUBST(GPGME_CONFIG_API_VERSION)
AC_SUBST(GPGME_CONFIG_LIBS)
AC_SUBST(GPGME_CONFIG_CFLAGS)
AC_SUBST(GPGME_CONFIG_HOST)
AC_SUBST(GPGME_CONFIG_AVAIL_LANG)

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
AC_SUBST(emacs_local_vars_begin, [['Local][ ][Variables:']])
AC_SUBST(emacs_local_vars_read_only, ['buffer-read-only: t'])
AC_SUBST(emacs_local_vars_end, ['End:'])

# Last check.
die=no
if test "$have_gpg_error" = "no"; then
   die=yes
   AC_MSG_NOTICE([[
***
*** You need libgpg-error to build this program.
**  This library is for example available at
***   ftp://ftp.gnupg.org/gcrypt/libgpg-error
*** (at least version $NEED_GPG_ERROR_VERSION is required.)
***]])
fi
if test "$have_libassuan" = "no"; then
   die=yes
   AC_MSG_NOTICE([[
***
*** You need libassuan to build this program.
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
AC_CONFIG_FILES(lang/cpp/Makefile lang/cpp/src/Makefile)
AC_CONFIG_FILES(lang/cpp/src/GpgmeppConfig.cmake.in)
AC_CONFIG_FILES(lang/cpp/src/GpgmeppConfigVersion.cmake)
AC_CONFIG_FILES(lang/cpp/src/gpgmepp_version.h)
AC_CONFIG_FILES(lang/qt/Makefile lang/qt/src/Makefile)
AC_CONFIG_FILES(lang/qt/src/QGpgmeConfig.cmake.in)
AC_CONFIG_FILES(lang/qt/src/QGpgmeConfigVersion.cmake)
AC_CONFIG_FILES(lang/qt/tests/Makefile)
AC_CONFIG_FILES(lang/qt/src/qgpgme_version.h)
AC_CONFIG_FILES([lang/Makefile lang/cl/Makefile lang/cl/gpgme.asd])
AM_COND_IF([HAVE_DOXYGEN], [AC_CONFIG_FILES([lang/qt/doc/Doxyfile])])
AC_CONFIG_FILES(lang/qt/doc/Makefile)
AC_CONFIG_FILES([lang/python/Makefile
		 lang/python/setup.py
		 lang/python/pyme/version.py
		 lang/python/tests/Makefile])
AC_OUTPUT

echo "
        GPGME v${VERSION} has been configured as follows:

        Revision:          mym4_revision  (mym4_revision_dec)
        Platform:          $host

        UI Server:         $uiserver
        FD Passing:        $use_descriptor_passing
        GPGME Pthread:     $have_pthread

        Language bindings: ${enabled_languages_v:-$enabled_languages}
"
if test "x${gpg_config_script_warn}" != x; then
cat <<G10EOF
        Mismatches between the target platform and the to
        be used libraries have been been detected for:
         ${gpg_config_script_warn}
        Please check above for warning messages.

G10EOF
fi
