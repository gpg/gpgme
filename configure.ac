# configure.ac for GPGME
# Copyright (C) 2000 Werner Koch (dd9jn)
# Copyright (C) 2001-2021 g10 Code GmbH
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

# (Process this file with autoconf to produce a configure script.)
AC_PREREQ([2.69])
min_automake_version="1.14"

# To build a release you need to create a tag with the version number
# "gpgme-n.m.k" and run "./autogen.sh --force".  Please bump the
# version number immediately after the release and do another commit
# and push so that the git magic is able to work.  If you start a new
# series by bumping the minor (m) remember to also create a tag named
# "gpgme-n.m-base" as the start point for beta numbering.  See below
# for the LT versions.
m4_define([mym4_package],[gpgme])
m4_define([mym4_major], [1])
m4_define([mym4_minor], [21])
m4_define([mym4_micro], [1])

# Below is m4 magic to extract and compute the git revision number,
# the decimalized short revision number, a beta version string and a
# flag indicating a development version (mym4_isbeta).  Note that the
# m4 processing is done by autoconf and not during the configure run.
m4_define([mym4_verslist], m4_split(m4_esyscmd([./autogen.sh --find-version] \
                           mym4_package mym4_major mym4_minor mym4_micro),[:]))
m4_define([mym4_isbeta],       m4_argn(2, mym4_verslist))
m4_define([mym4_version],      m4_argn(4, mym4_verslist))
m4_define([mym4_revision],     m4_argn(7, mym4_verslist))
m4_define([mym4_revision_dec], m4_argn(8, mym4_verslist))
m4_esyscmd([echo ]mym4_version[>VERSION])
AC_INIT([mym4_package],[mym4_version],[https://bugs.gnupg.org])

# LT Version numbers, remember to change them just *before* a release.
#   (Code changed:			REVISION++)
#   (Interfaces added/removed/changed:	CURRENT++, REVISION=0)
#   (Interfaces added:			AGE++)
#   (Interfaces removed:		AGE=0)
#
LIBGPGME_LT_CURRENT=41
LIBGPGME_LT_AGE=30
LIBGPGME_LT_REVISION=0

# If there is an ABI break in gpgmepp or qgpgme also bump the
# version in IMPORTED_LOCATION in the GpgmeppConfig-w32.cmake.in.in

LIBGPGMEPP_LT_CURRENT=24
LIBGPGMEPP_LT_AGE=18
LIBGPGMEPP_LT_REVISION=0

LIBQGPGME_LT_CURRENT=18
LIBQGPGME_LT_AGE=3
LIBQGPGME_LT_REVISION=0
################################################

AC_SUBST(LIBGPGME_LT_CURRENT)
AC_SUBST(LIBGPGME_LT_AGE)
AC_SUBST(LIBGPGME_LT_REVISION)

AC_SUBST(LIBGPGMEPP_LT_CURRENT)
AC_SUBST(LIBGPGMEPP_LT_AGE)
AC_SUBST(LIBGPGMEPP_LT_REVISION)

AC_SUBST(LIBQGPGME_LT_CURRENT)
AC_SUBST(LIBQGPGME_LT_AGE)
AC_SUBST(LIBQGPGME_LT_REVISION)

# If the API is changed in an incompatible way: increment the next counter.
GPGME_CONFIG_API_VERSION=1
##############################################

NEED_GPG_ERROR_VERSION=1.36
NEED_LIBASSUAN_API=2
NEED_LIBASSUAN_VERSION=2.4.2


VERSION_MAJOR=mym4_major
VERSION_MINOR=mym4_minor
VERSION_MICRO=mym4_micro

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/gpgme.h.in])
AC_CONFIG_HEADERS([conf/config.h])
AM_INIT_AUTOMAKE([serial-tests dist-bzip2 no-dist-gzip])
AM_MAINTAINER_MODE
AC_CANONICAL_HOST
AM_SILENT_RULES
AC_ARG_VAR(SYSROOT,[locate config scripts also below that directory])

# Enable GNU extensions on systems that have them.
AC_USE_SYSTEM_EXTENSIONS

# Taken from mpfr-4.0.1, then modified for LDADD_FOR_TESTS_KLUDGE
dnl Under Linux, make sure that the old dtags are used if LD_LIBRARY_PATH
dnl is defined. The issue is that with the new dtags, LD_LIBRARY_PATH has
dnl the precedence over the run path, so that if a compatible MPFR library
dnl is installed in some directory from $LD_LIBRARY_PATH, then the tested
dnl MPFR library will be this library instead of the MPFR library from the
dnl build tree. Other OS with the same issue might be added later.
dnl
dnl References:
dnl   https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=859732
dnl   http://lists.gnu.org/archive/html/libtool/2017-05/msg00000.html
dnl
dnl We need to check whether --disable-new-dtags is supported as alternate
dnl linkers may be used (e.g., with tcc: CC=tcc LD=tcc).
dnl
case $host in
  *-*-linux*)
    if test -n "$LD_LIBRARY_PATH"; then
      saved_LDFLAGS="$LDFLAGS"
      LDADD_FOR_TESTS_KLUDGE="-Wl,--disable-new-dtags"
      LDFLAGS="$LDFLAGS $LDADD_FOR_TESTS_KLUDGE"
      AC_MSG_CHECKING(whether --disable-new-dtags is supported by the linker)
      AC_LINK_IFELSE([AC_LANG_SOURCE([[
int main (void) { return 0; }
      ]])],
      [AC_MSG_RESULT(yes (use it since LD_LIBRARY_PATH is set))],
      [AC_MSG_RESULT(no)
       LDADD_FOR_TESTS_KLUDGE=""
      ])
      LDFLAGS="$saved_LDFLAGS"
    fi
    ;;
esac
AC_SUBST([LDADD_FOR_TESTS_KLUDGE])

AH_VERBATIM([_REENTRANT],
[/* To allow the use of GPGME in multithreaded programs we have to use
  special features from the library.
  IMPORTANT: gpgme is not yet fully reentrant and you should use it
  only from one thread.  */
#ifndef _REENTRANT
# define _REENTRANT 1
#endif])

AC_PROG_CC
AC_PROG_CPP
AC_PROG_CXX

# Note: A suitable gitlog-to-changelog script can be found in GnuPG master.
AC_CHECK_PROGS(GITLOG_TO_CHANGELOG, gitlog-to-changelog, [gitlog-to-changelog])

AC_SUBST(VERSION_MAJOR)
AC_SUBST(VERSION_MINOR)
AC_SUBST(VERSION_MICRO)

VERSION_NUMBER=m4_esyscmd(printf "0x%02x%02x%02x" mym4_major \
                          mym4_minor mym4_micro)
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
        AC_DEFINE(_DARWIN_C_SOURCE, 1,
                  Expose all libc features (__DARWIN_C_FULL).)
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
have_macos_system=no
build_w32_glib=no
build_w32_qt=no
available_languages="cl cpp python qt qt5 qt6"
default_languages="cl cpp python qt"
case "${host}" in
    x86_64-*mingw32*)
        have_w64_system=yes
        ;;
    *-linux-androideabi)
        have_android_system=yes
        ;;
    *-apple-darwin*)
        have_macos_system=yes
        ;;
esac
case "${host}" in
    *-mingw32*)
	have_dosish_system=yes
        have_w32_system=yes
        GPG_DEFAULT='c:\\gnupg\\gpg.exe'
	GPGSM_DEFAULT='c:\\gnupg\\gpgsm.exe'
        GPGCONF_DEFAULT='c:\\gnupg\\gpgconf.exe'
        G13_DEFAULT='c:\\gnupg\\g13.exe'
        #component_system='COM+'

	AM_PATH_GLIB_2_0
	AC_ARG_ENABLE(w32-glib,
	    AS_HELP_STRING([--enable-w32-glib],[build GPGME Glib for W32]),
	    		   build_w32_glib=$enableval)
       ;;
    *)

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

if test "$have_android_system" = yes; then
   AC_DEFINE(HAVE_ANDROID_SYSTEM,1, [Defined if we build for an Android system])
fi
AM_CONDITIONAL(HAVE_ANDROID_SYSTEM, test "$have_android_system" = yes)

if test "$have_macos_system" = yes; then
   AC_DEFINE(HAVE_MACOS_SYSTEM,1,
             [Defined if we build for an MacOS system])
fi
AM_CONDITIONAL(HAVE_MACOS_SYSTEM, test "$have_macos_system" = yes)

AM_CONDITIONAL(BUILD_W32_GLIB, test "$build_w32_glib" = yes)


AC_ARG_ENABLE([fixed-path],
              AS_HELP_STRING([--enable-fixed-path=PATH],
                             [locate binaries only via this PATH]),
              [fixed_search_path="$enableval"],
              [fixed_search_path=""])
if test x$fixed_search_path != x ; then
  AC_DEFINE_UNQUOTED(FIXED_SEARCH_PATH, "$fixed_search_path",
                    [Locate binaries only via this PATH])
fi


# Note: You need to declare all possible languages also in
#       lang/Makefile.am's DIST_SUBDIRS.
AC_ARG_ENABLE([languages],
              AS_HELP_STRING([--enable-languages=languages],
                             [enable only specific language bindings:
                              cl cpp python qt qt5 qt6 (qt selects qt5 or qt6,
                              and qt5 and qt6 exclude each other)]),
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

# Check whether Qt5 and/or Qt6 are enabled explicitly
want_qt5="no";
LIST_MEMBER("qt5", $enabled_languages)
if test "$found" = "1"; then
    want_qt5="yes";
    # Remove qt5; further down qt will be added
    enabled_languages=$(echo $enabled_languages | sed 's/qt5//')
fi
want_qt6="no";
LIST_MEMBER("qt6", $enabled_languages)
if test "$found" = "1"; then
    want_qt6="yes";
    # Remove qt6; further down qt will be added
    enabled_languages=$(echo $enabled_languages | sed 's/qt6//')
fi
if test "$want_qt5" = "yes" -a "$want_qt6" = "yes"; then
    AC_MSG_ERROR([[
***
*** The bindings for Qt5 and Qt6 cannot be built simultaneously.
***]])
fi

# Ensure that pkg-config is available for all calls of FIND_QT5/FIND_QT6
PKG_PROG_PKG_CONFIG

# If the generic qt is enabled, then check for Qt5 or Qt6 (in this order)
LIST_MEMBER("qt", $enabled_languages)
if test "$found" = "1"; then
    # Remove the generic qt (qt5 and qt6 have already been removed)
    enabled_languages=$(echo $enabled_languages | sed 's/qt//')
    FIND_QT5
    if test "$have_qt5_libs" = "yes"; then
        want_qt5="yes";
    else
        FIND_QT6
        if test "$have_qt6_libs" = "yes"; then
            want_qt6="yes";
        else
            if test "$explicit_languages" = "1"; then
                AC_MSG_ERROR([[
***
*** Qt5 (Qt5Core) or Qt6 (Qt6Core) is required for the Qt binding.
***]])
            else
                AC_MSG_WARN([[
***
*** Qt5 (Qt5Core) and Qt6 (Qt6Core) not found. Qt Binding will be disabled.
***]])
            fi
        fi
    fi
elif test "$want_qt5" = "yes"; then
    FIND_QT5
    if test "$have_qt5_libs" != "yes"; then
        AC_MSG_ERROR([[
***
*** Qt5 (Qt5Core) is required for the Qt 5 binding.
***]])
    fi
elif test "$want_qt6" = "yes"; then
    FIND_QT6
    if test "$have_qt6_libs" != "yes"; then
        AC_MSG_ERROR([[
***
*** Qt6 (Qt6Core) is required for the Qt 6 binding.
***]])
    fi
fi

# Check that cpp is enabled if qt5 or qt6 is enabled
if test "$want_qt5" = "yes" -o "$want_qt6" = "yes"; then
    LIST_MEMBER("cpp", $enabled_languages)
    if test "$found" = "0"; then
        AC_MSG_ERROR([[
***
*** The Qt bindings depend on the C++ binding.
***]])
    fi
fi

# Enable C++ 17 if qt6 is requested
if test "$want_qt6" = "yes"; then
    AX_CXX_COMPILE_STDCXX(17, noext, optional)
    if test "$HAVE_CXX17" != "1"; then
        if test "$explicit_languages" = "1"; then
            AC_MSG_ERROR([[
***
*** A compiler with c++17 support is required for the Qt 6 binding.
***]])
        else
            want_qt6="no"
            AC_MSG_WARN([[
***
*** No c++17 support detected. Qt 6 binding will be disabled.
***]])
        fi
    fi
fi

# Enable C++ 11 if cpp is requested (unless C++ 17 was already enabled)
LIST_MEMBER("cpp", $enabled_languages)
if test "$found" = "1" -a "$HAVE_CXX17" != "1"; then
    AX_CXX_COMPILE_STDCXX(11, noext, optional)
    if test "$HAVE_CXX11" != "1"; then
        if test "$explicit_languages" = "1"; then
            AC_MSG_ERROR([[
***
*** A compiler with c++11 support is required for the C++ binding.
***]])
        else
            enabled_languages=$(echo $enabled_languages | sed 's/cpp//')
            want_qt5="no"
            AC_MSG_WARN([[
***
*** No c++11 support detected. C++ and Qt 5 bindings will be disabled.
***]])
        fi
    fi
fi

# Now append qt to the list of language bindings
if test "$want_qt5" = "yes" -o "$want_qt6" = "yes"; then
    enabled_languages=$(echo $enabled_languages qt)
fi

# Check whether compiler supports visibility attribute (if cpp language is enabled)
LIST_MEMBER("cpp", $enabled_languages)
if test "$found" = "1"; then
    AX_GCC_FUNC_ATTRIBUTE(visibility)
    if test "$ax_cv_have_func_attribute_visibility" = "yes"; then
        GPGME_CPP_CFLAGS="$GPGME_CPP_CFLAGS -fvisibility=hidden"
        if test "$want_qt5" = "yes"; then
            GPGME_QT5_CFLAGS="$GPGME_QT5_CFLAGS -fvisibility=hidden"
        fi
        if test "$want_qt6" = "yes"; then
            GPGME_QT6_CFLAGS="$GPGME_QT6_CFLAGS -fvisibility=hidden"
        fi
    fi
fi
AC_SUBST(GPGME_CPP_CFLAGS)

AM_CONDITIONAL(WANT_QT5, test "$want_qt5" = yes)
AM_CONDITIONAL(WANT_QT6, test "$want_qt6" = yes)

# Check for tools for building the Qt binding docs
if test "$want_qt5" = "yes" -o "$want_qt6" = "yes"; then
    AC_CHECK_PROGS([DOXYGEN], [doxygen])
    if test -z "$DOXYGEN"; then
        # This is not highlighted because it's not really important.
        AC_MSG_WARN([Doxygen not found - Qt binding doc will not be built.])
    fi
    AC_CHECK_PROGS([GRAPHVIZ], [dot])
    if test -z "$GRAPHVIZ"; then
        AC_MSG_WARN([Graphviz not found - Qt binding doc will not have diagrams.])
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
LIST_MEMBER("python", $enabled_languages)
found_py=$found
if test "$found_py" = "1"; then
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
        # Reset the version collecting vars.
	PYTHONS=
	PYTHON_VERSIONS=

	if test "$found_py" = "1" -o "$found_py3" = "1"; then
	  # Reset everything, so that we can look for another Python.
          m4_foreach([mym4pythonver],
                     [[2.7],[3.4],[3.5],[3.6],[3.7],[3.8],[3.9],[3.10],
                      [3.11],[3.12],[all]],
           [unset PYTHON
	    unset PYTHON_VERSION
	    unset PYTHON_CPPFLAGS
	    unset PYTHON_LDFLAGS
	    unset PYTHON_LIBS
	    unset PYTHON_SITE_PKG
	    unset PYTHON_EXTRA_LIBS
	    unset PYTHON_EXTRA_LDFLAGS
	    unset ac_cv_path_PYTHON
	    unset am_cv_pathless_PYTHON
	    unset am_cv_python_version
	    unset am_cv_python_platform
	    unset am_cv_python_pythondir
	    unset am_cv_python_pyexecdir
	    AM_PATH_PYTHON(mym4pythonver, [
		AX_PYTHON_DEVEL
		if test "$PYTHON_VERSION"; then
			PYTHONS="$(echo $PYTHONS $PYTHON)"
			PYTHON_VERSIONS="$(echo $PYTHON_VERSIONS $PYTHON_VERSION)"
		fi
	    ], :, m4_if([mym4pythonver],[all],[],[python]mym4pythonver))
           ])
	fi

	# Recover some values lost in the second attempt to find Python.
	PYTHON="$(echo $PYTHONS | cut -d ' ' -f 1)"
	PYTHON_VERSION="$(echo $PYTHON_VERSIONS | cut -d ' ' -f 1)"

	# Remove duplicates.
	PYTHONS="$(echo $PYTHONS | tr '[[:space:]]' '\n' | sort | uniq | tr '\n' ' ' | sed -e 's/ $//')"
	PYTHON_VERSIONS="$(echo $PYTHON_VERSIONS | tr '[[:space:]]' '\n' | sort | uniq | tr '\n' ' ' | sed -e 's/ $//')"

	if test "$PYTHON_VERSIONS"; then
	   enabled_languages_v=$(echo $enabled_languages | sed -Ee "s/python[[23]]?/python ($PYTHON_VERSIONS)/")
	   enabled_languages=$(echo $enabled_languages | sed -Ee "s/python[[23]]?/python/")
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
BUILD_VERSION=`echo "$PACKAGE_VERSION" | sed 's/\([0-9.]*\).*/\1./'`
changequote([,])dnl
BUILD_VERSION="${BUILD_VERSION}mym4_revision_dec"
BUILD_FILEVERSION=`echo "${BUILD_VERSION}" | tr . ,`
AC_SUBST(BUILD_VERSION)
AC_SUBST(BUILD_FILEVERSION)

AC_ARG_ENABLE([build-timestamp],
  AS_HELP_STRING([--enable-build-timestamp],
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
  AS_HELP_STRING([--disable-gpgconf-test],[disable GPGCONF regression test]),
         run_gpgconf_test=$enableval)
AM_CONDITIONAL(RUN_GPGCONF_TESTS, test "$run_gpgconf_test" = "yes")

run_gpg_test="yes"
AC_ARG_ENABLE(gpg-test,
  AS_HELP_STRING([--disable-gpg-test],[disable GPG regression test]),
         run_gpg_test=$enableval)
AM_CONDITIONAL(RUN_GPG_TESTS, test "$run_gpg_test" = "yes")

run_gpgsm_test="yes"
AC_ARG_ENABLE(gpgsm-test,
  AS_HELP_STRING([--disable-gpgsm-test],[disable GPGSM regression test]),
         run_gpgsm_test=$enableval)
AM_CONDITIONAL(RUN_GPGSM_TESTS, test "$run_gpgsm_test" = "yes")

run_g13_test="yes"
AC_ARG_ENABLE(g13-test,
  AS_HELP_STRING([--disable-g13-test],[disable G13 regression test]),
         run_g13_test=$enableval)
AM_CONDITIONAL(RUN_G13_TESTS, test "$run_g13_test" = "yes")


# Checks for header files.
AC_CHECK_HEADERS_ONCE([locale.h sys/select.h sys/uio.h argp.h stdint.h
                       unistd.h poll.h sys/time.h sys/types.h sys/stat.h])


# Type checks.
AC_C_INLINE
AC_C_FLEXIBLE_ARRAY_MEMBER
AC_CHECK_SIZEOF(unsigned int)
AC_SYS_LARGEFILE
AC_TYPE_OFF_T
AC_TYPE_UINTPTR_T

# We require uint64_t
if test "$ac_cv_header_stdint_h" != yes; then
   AC_MSG_ERROR([[
***
*** No stdint.h and thus no uint64_t type.  Can't build this library.
***]])
fi


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
    CFLAGS="$CFLAGS -Wno-format-y2k"

    # If -Wno-missing-field-initializers is supported we can expect a
    # a larger set of warning options.
    AC_MSG_CHECKING([if gcc supports -Wno-missing-field-initializers])
    _gcc_cflags_save=$CFLAGS
    CFLAGS="-Wno-missing-field-initializers"
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],_gcc_wopt=yes,_gcc_wopt=no)
    AC_MSG_RESULT($_gcc_wopt)
    CFLAGS=$_gcc_cflags_save;
    if test x"$_gcc_wopt" = xyes ; then
      CFLAGS="$CFLAGS -Wno-missing-field-initializers"
      CFLAGS="$CFLAGS -Wno-sign-compare"
      CFLAGS="$CFLAGS -Wno-format-zero-length"
      CFLAGS="$CFLAGS -Wno-format-truncation"
      CFLAGS="$CFLAGS -Wno-sizeof-pointer-div"
    fi
    if test "$USE_MAINTAINER_MODE" = "yes"; then
        if test x"$_gcc_wopt" = xyes ; then
          CFLAGS="$CFLAGS -W -Wextra -Wbad-function-cast"
          CFLAGS="$CFLAGS -Wwrite-strings"
          CFLAGS="$CFLAGS -Wdeclaration-after-statement"
        fi
        CFLAGS="$CFLAGS -Wformat -Wformat-security"
        CXXFLAGS="$CXXFLAGS -Wall -Wextra -Wno-shadow"

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
if test $GLIBC21 = yes -o $have_w32_system = yes; then
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

AM_CONDITIONAL(USE_GPGRT_CONFIG, [test -n "$GPGRT_CONFIG" \
                                  -a "$ac_cv_path_GPG_ERROR_CONFIG" = no])

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

# Check for getgid etc
AC_CHECK_FUNCS(getgid getegid closefrom nanosleep)


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

use_descriptor_passing=yes
AC_ARG_ENABLE(fd-passing,
  AS_HELP_STRING([--disable-fd-passing],[do not use FD passing]),
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


# Option --disable-linux-getdents
#
# By default we use SYS_getdents on Linux to optimize fd closing
# before an exec.  This option allows to switch this optimization off.
use_linux_getdents=yes
AC_ARG_ENABLE(linux-getdents,
              AS_HELP_STRING([--disable-linux-getdents],
                             [do not use SYS_getdents on Linux]),
              use_linux_getdents=$enableval)
if test "$use_linux_getdents" = "yes"; then
    case "${host}" in
        *-*-linux*)
           AC_DEFINE(USE_LINUX_GETDENTS,1,
                     [Defined if SYS_getdents can be used on Linux])
           ;;
    esac
fi


#
# Add a few constants to help porting to W32
#
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

/* Under Windows we use the gettext code from gpgrt.  */
#define GPG_ERR_ENABLE_GETTEXT_MACROS 1

/* Under WindowsCE we need gpg-error's strerror macro.  */
#define GPG_ERR_ENABLE_ERRNO_MACROS 1

#define CRIGHTBLURB "Copyright (C) 2000 Werner Koch\n" \
                    "Copyright (C) 2001--2021 g10 Code GmbH\n"
])


# Substitution used for gpgme-config and gpgme.pc
GPGME_CONFIG_LIBS="-lgpgme"
GPGME_CONFIG_CFLAGS=""
GPGME_CONFIG_HOST="$host"
GPGME_CONFIG_AVAIL_LANG="$enabled_languages"

case "$includedir" in
  /usr/include|/include) ;;
  '${prefix}/include')
    if test "$prefix" != / -a "$prefix" != /usr; then
      if test -z "$GPGME_CONFIG_CFLAGS"; then
        GPGME_CONFIG_CFLAGS="-I\${includedir}"
      else
        GPGME_CONFIG_CFLAGS="-I\${includedir} $GPGME_CONFIG_CFLAGS"
      fi
    fi
    ;;
  *)
    if test -z "$GPGME_CONFIG_CFLAGS"; then
      GPGME_CONFIG_CFLAGS="-I\${includedir}"
    else
      GPGME_CONFIG_CFLAGS="-I\${includedir} $GPGME_CONFIG_CFLAGS"
    fi
    ;;
esac
case "$libdir" in
  /usr/lib|/usr/lib64|/lib|/lib64) ;;
  '${exec_prefix}/lib'|'${exec_prefix}/lib64')
    if test "$exec_prefix" = "NONE"; then
      if test "$prefix" != / -a "$prefix" != /usr; then
        GPGME_CONFIG_LIBS="-L\${libdir} $GPGME_CONFIG_LIBS"
      fi
    elif test "$exec_prefix" != / -a "$exec_prefix" != /usr; then
      GPGME_CONFIG_LIBS="-L\${libdir} $GPGME_CONFIG_LIBS"
    fi
    ;;
  *) GPGME_CONFIG_LIBS="-L\${libdir} $GPGME_CONFIG_LIBS" ;;
esac

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
***   https://www.gnupg.org/ftp/gcrypt/libgpg-error/
*** (at least version $NEED_GPG_ERROR_VERSION is required.)
***]])
fi
if test "$have_libassuan" = "no"; then
   die=yes
   AC_MSG_NOTICE([[
***
*** You need libassuan to build this program.
*** This library is for example available at
***   https://www.gnupg.org/ftp/gcrypt/libassuan/
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
                tests/json/Makefile
		doc/Makefile
                src/versioninfo.rc
                src/gpgme.pc
                src/gpgme-glib.pc
                src/gpgme.h)
AC_CONFIG_FILES(src/gpgme-config, chmod +x src/gpgme-config)
AC_CONFIG_FILES(lang/cpp/Makefile lang/cpp/src/Makefile)
AC_CONFIG_FILES(lang/cpp/tests/Makefile)
AC_CONFIG_FILES(lang/cpp/src/GpgmeppConfig-w32.cmake.in)
AC_CONFIG_FILES(lang/cpp/src/GpgmeppConfig.cmake.in)
AC_CONFIG_FILES(lang/cpp/src/GpgmeppConfigVersion.cmake)
AC_CONFIG_FILES(lang/cpp/src/gpgmepp_version.h)
AC_CONFIG_FILES(lang/qt/Makefile lang/qt/src/Makefile)
if test "$want_qt5" = "yes"; then
    AC_CONFIG_FILES(lang/qt/src/QGpgmeConfig-w32.cmake.in)
    AC_CONFIG_FILES(lang/qt/src/QGpgmeConfig.cmake.in)
    AC_CONFIG_FILES(lang/qt/src/QGpgmeConfigVersion.cmake)
fi
if test "$want_qt6" = "yes"; then
    AC_CONFIG_FILES(lang/qt/src/QGpgmeQt6Config-w32.cmake.in)
    AC_CONFIG_FILES(lang/qt/src/QGpgmeQt6Config.cmake.in)
    AC_CONFIG_FILES(lang/qt/src/QGpgmeQt6ConfigVersion.cmake)
fi
AC_CONFIG_FILES(lang/qt/tests/Makefile)
AC_CONFIG_FILES(lang/qt/src/qgpgme_version.h)
AC_CONFIG_FILES([lang/Makefile lang/cl/Makefile lang/cl/gpgme.asd])
AM_COND_IF([HAVE_DOXYGEN], [AC_CONFIG_FILES([lang/qt/doc/Doxyfile])])
AC_CONFIG_FILES([lang/js/Makefile lang/js/src/Makefile
                 lang/js/BrowserTestExtension/Makefile
                 lang/js/DemoExtension/Makefile])
AC_CONFIG_FILES(lang/qt/doc/Makefile)
AC_CONFIG_FILES([lang/python/Makefile
		 lang/python/version.py
		 lang/python/tests/Makefile
		 lang/python/src/Makefile
		 lang/python/examples/Makefile
		 lang/python/doc/Makefile])
AC_CONFIG_FILES([lang/python/setup.py], [chmod a+x lang/python/setup.py])
AC_OUTPUT

if test "$want_qt5" = "yes"; then
    enabled_languages_v=$(echo ${enabled_languages_v:-$enabled_languages} | sed "s/qt/qt (Qt 5)/")
elif test "$want_qt6" = "yes"; then
    enabled_languages_v=$(echo ${enabled_languages_v:-$enabled_languages} | sed "s/qt/qt (Qt 6)/")
fi

echo "
        GPGME v${VERSION} has been configured as follows:

        Revision:          mym4_revision  (mym4_revision_dec)
        Platform:          $host

        UI Server:         $uiserver
        FD Passing:        $use_descriptor_passing

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
