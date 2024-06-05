# configure.ac for QGpgME
# Copyright (C) 2000 Werner Koch (dd9jn)
# Copyright (C) 2001-2021,2024 g10 Code GmbH
#
# This file is part of QGpgME.
#
# QGpgME is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# QGpgME is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <https://gnu.org/licenses/>.
# SPDX-License-Identifier: GPL-2.0-or-later

# (Process this file with autoconf to produce a configure script.)
AC_PREREQ([2.69])
min_automake_version="1.14"

# To build a release you need to create a tag with the version number
# "qgpgme-n.m.k" and run "./autogen.sh --force".  Please bump the
# version number immediately after the release and do another commit
# and push so that the git magic is able to work.  If you start a new
# series by bumping the minor (m) remember to also create a tag named
# "qgpgme-n.m-base" as the start point for beta numbering.  See below
# for the LT versions.
m4_define([mym4_package],[qgpgme])
m4_define([mym4_major], [1])
m4_define([mym4_minor], [24])
m4_define([mym4_micro], [0])

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
# If there is an ABI break in qgpgme also bump the version in
# IMPORTED_LOCATION in QGpgme[Qt6]Config-w32.cmake.in.in
LIBQGPGME_LT_CURRENT=20
LIBQGPGME_LT_AGE=5
LIBQGPGME_LT_REVISION=1
################################################

AC_SUBST(LIBQGPGME_LT_CURRENT)
AC_SUBST(LIBQGPGME_LT_AGE)
AC_SUBST(LIBQGPGME_LT_REVISION)

# If the API is changed in an incompatible way: increment the next counter.
##GPGME_CONFIG_API_VERSION=1
##############################################

NEED_GPG_ERROR_VERSION=1.47

# We need GpgME and GpgME++ matching the minor version of QGpgME
NEED_GPGME_VERSION=mym4_major.mym4_minor.0
NEED_GPGMEPP_VERSION=mym4_major.mym4_minor.0

VERSION_MAJOR=mym4_major
VERSION_MINOR=mym4_minor
VERSION_MICRO=mym4_micro

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
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

#
# Specify how we support our local modification of libtool for Windows
# 64-bit.  Options are:
#
# (1) apply: when appying patch fails, it results failure of entire build
# (2) never: never apply the patch (no try)
# (3) try: use patched if it goes well, use original if fails
#
AC_ARG_WITH([libtool-modification],
  AS_HELP_STRING([--with-libtool-modification=apply|never|try],
                 [how to handle libtool modification (default=never)]),
                 build_libtool_modification=$withval,
                 build_libtool_modification=never)

#
# Apply a patch (locally maintained one of ours) to libtool
#
case $host in
  x86_64-*mingw32*)
AC_CONFIG_COMMANDS([libtool-patch],[[
  if test "$build_selection" = never; then
    echo "patch not applied"
  elif (mv -f libtool libtool.orig; \
        sed -f $srcdir/build-aux/libtool-patch.sed libtool.orig >libtool); then
    echo "applied successfully"
  elif test "$build_selection" = try; then
    mv -f libtool.orig libtool
    echo "patch failed, thus, using original"
  else
    echo "patch failed"
    as_fn_exit 1
  fi
]],[build_selection=$build_libtool_modification])
  ;;
  *)
  ;;
esac

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
build_w32_qt=no
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


# Option --enable-reduce-relocations
#
# Allow building the Qt 6 bindings explicitly with -fPIC if the automatic
# detection fails. Note: We assume that this flag is always available (unless
# we built for Windows).
AC_ARG_ENABLE([reduce-relocations],
              AS_HELP_STRING([--enable-reduce-relocations],
                             [build Qt 6 bindings with -fPIC (default is
                              auto)]),
              [use_reduce_relocations="$enableval"],
              [use_reduce_relocations=""])

# Option --enable-no-direct-extern-access
#
# Some distributions build Qt 6 with -mno-direct-extern-access. Libraries and
# applications using Qt then must also be build with this flag. As workaround
# for a bug in Qt's pkgconfig files which don't have this flag we allow
# building with this flag explicitly.
AC_LANG_PUSH(C++)
AX_CHECK_COMPILE_FLAG([-mno-direct-extern-access],
                      [have_no_direct_extern_access="yes"],
                      [have_no_direct_extern_access="no"],
                      [-Werror])
AC_LANG_POP()
AC_ARG_ENABLE([no-direct-extern-access],
              AS_HELP_STRING([--enable-no-direct-extern-access],
                             [build Qt 6 bindings with
                              -mno-direct-extern-access (default is auto)]),
              [use_no_direct_extern_access="$enableval"],
              [use_no_direct_extern_access=""])

# Option --enable-qt-version
AC_ARG_ENABLE([qt-version],
              AS_HELP_STRING([--enable-qt-version=version],
                             [build bindings for specific Qt version:
                              auto 5 6 (auto selects Qt 6 or Qt 5)]),
                             [qt_version=`echo $enableval | \
                             tr '[A-Z]' '[a-z]'`],
                             [qt_version="auto"])
case "$qt_version" in
  auto | 5 | 6) ;;
  *)
    AC_MSG_ERROR([invalid Qt version specified: $qt_version])
  ;;
esac

# Ensure that pkg-config is available for all calls of FIND_QT5/FIND_QT6
PKG_PROG_PKG_CONFIG

# If the generic qt is enabled, then check for Qt 6 or Qt 5 (in this order)
if test "$qt_version" = "auto"; then
    FIND_QT6
    if test "$have_qt6_libs" = "yes"; then
        qt_version="6";
    else
        FIND_QT5
        if test "$have_qt5_libs" = "yes"; then
            qt_version="5";
        else
            AC_MSG_ERROR([[
***
*** Qt6 (Qt6Core) or Qt5 (Qt5Core) is required for the Qt binding.
***]])
        fi
    fi
elif test "$qt_version" = "5"; then
    FIND_QT5
    if test "$have_qt5_libs" != "yes"; then
        AC_MSG_ERROR([[
***
*** Qt5 (Qt5Core) is required for the Qt 5 binding.
***]])
    fi
elif test "$qt_version" = "6"; then
    FIND_QT6
    if test "$have_qt6_libs" != "yes"; then
        AC_MSG_ERROR([[
***
*** Qt6 (Qt6Core) is required for the Qt 6 binding.
***]])
    fi
fi

# Require C++ 17
AX_CXX_COMPILE_STDCXX(17, noext, optional)
if test "$HAVE_CXX17" != "1"; then
    AC_MSG_ERROR([[
***
*** A compiler with c++17 support is required for the Qt binding.
***]])
fi

# Check whether compiler supports visibility attribute
AX_GCC_FUNC_ATTRIBUTE(visibility)
if test "$ax_cv_have_func_attribute_visibility" = "yes"; then
    if test "$qt_version" = "5"; then
        GPGME_QT5_CFLAGS="$GPGME_QT5_CFLAGS -fvisibility=hidden"
    elif test "$qt_version" = "6"; then
        GPGME_QT6_CFLAGS="$GPGME_QT6_CFLAGS -fvisibility=hidden"
    fi
fi

AM_CONDITIONAL(WANT_QT5, test "$qt_version" = "5")
AM_CONDITIONAL(WANT_QT6, test "$qt_version" = "6")

# Check for tools for building the Qt binding docs
AC_CHECK_PROGS([DOXYGEN], [doxygen])
if test -z "$DOXYGEN"; then
    # This is not highlighted because it's not really important.
    AC_MSG_WARN([Doxygen not found - Qt binding doc will not be built.])
fi
AC_CHECK_PROGS([GRAPHVIZ], [dot])
if test -z "$GRAPHVIZ"; then
    AC_MSG_WARN([Graphviz not found - Qt binding doc will not have diagrams.])
fi

AM_CONDITIONAL([HAVE_DOXYGEN],
               [test -n "$DOXYGEN"])
if test -n "$GRAPHVIZ"; then
    HAVE_DOT="YES"
else
    HAVE_DOT="NO"
fi
AC_SUBST(HAVE_DOT)

#
# Provide information about the build.
#
BUILD_REVISION="mym4_revision"
AC_SUBST(BUILD_REVISION)
AC_DEFINE_UNQUOTED(BUILD_REVISION, "$BUILD_REVISION",
                   [GIT commit id revision used to build this package])


#
# Options to disable some regression tests
#
run_tests="yes"
AC_ARG_ENABLE(tests,
  AS_HELP_STRING([--disable-tests], [disable regression tests]),
  run_tests=$enableval)
AM_CONDITIONAL(RUN_GPG_TESTS, test "$run_tests" = "yes")


# Checks for header files.
AC_CHECK_HEADERS_ONCE([unistd.h])


# Type checks.
#AC_C_INLINE
#AC_C_FLEXIBLE_ARRAY_MEMBER
AC_CHECK_SIZEOF(unsigned int)
AC_SYS_LARGEFILE
#AC_TYPE_OFF_T
#AC_TYPE_UINTPTR_T


# Checks for compiler features.
if test "$GCC" = yes; then
    if test "$USE_MAINTAINER_MODE" = "yes"; then
        CXXFLAGS="$CXXFLAGS -Wall -Wextra -Wno-shadow"
    fi
fi


# Checks for library functions.
AC_MSG_NOTICE([checking for libraries])

# Checking for libgpg-error.
have_gpg_error=no
AM_PATH_GPG_ERROR("$NEED_GPG_ERROR_VERSION",
                  have_gpg_error=yes, have_gpg_error=no)
AC_DEFINE(GPG_ERR_SOURCE_DEFAULT, GPG_ERR_SOURCE_GPGME,
          [The default error source for GPGME.])

AM_CONDITIONAL(USE_GPGRT_CONFIG, [test -n "$GPGRT_CONFIG" \
                                  -a "$ac_cv_path_GPG_ERROR_CONFIG" = no])

# Check for gpgme and gpgmepp.
have_gpgme=no
have_gpgmepp=no
# Check if qgpgme is built as nested package of gpgme
builddir=`pwd`
if test "${srcdir%/lang/qt}/lang/qt" == "$srcdir" -a \
        "${builddir%/lang/qt}/lang/qt" == "$builddir"; then
  AC_MSG_CHECKING(for GpgME - assuming nested build)
  gpgme_build_dir=${builddir%/lang/qt}
  if test -f "$gpgme_build_dir/src/gpgme.h"; then
    GPGME_CFLAGS="-I$gpgme_build_dir/src"
    GPGME_LIBS="$gpgme_build_dir/src/libgpgme.la"
    have_gpgme=yes
    AC_MSG_RESULT(yes)
  else
    AC_MSG_RESULT(no)
  fi
  AC_MSG_CHECKING(for GpgME++ - assuming nested build)
  gpgmepp_build_dir=${builddir%/lang/qt}/lang/cpp
  if test -f "$gpgmepp_build_dir/src/gpgmepp_version.h"; then
    GPGMEPP_CFLAGS="-I$gpgmepp_build_dir/src"
    GPGMEPP_LIBS="$gpgmepp_build_dir/src/libgpgmepp.la"
    have_gpgmepp=yes
    AC_MSG_RESULT(yes)
  else
    AC_MSG_RESULT(no)
  fi
fi

if test "$have_gpgme" = "no"; then
  AM_PATH_GPGME("$NEED_GPGME_VERSION",
                have_gpgme=yes, have_gpgme=no)
fi
if test "$have_gpgmepp" = "no"; then
  AM_PATH_GPGMEPP("$NEED_GPGMEPP_VERSION",
                  have_gpgmepp=yes, have_gpgmepp=no)
fi

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
if test "$have_gpgme" = "no"; then
   die=yes
   AC_MSG_NOTICE([[
***
*** You need gpgme to build this program.
*** This library is for example available at
***   https://www.gnupg.org/ftp/gcrypt/gpgme/
*** (at least version $NEED_GPGME_VERSION is required).
***]])
fi
if test "$have_gpgmepp" = "no"; then
   die=yes
   AC_MSG_NOTICE([[
***
*** You need gpgmepp to build this program.
*** This library is for example available at
***   https://www.gnupg.org/ftp/gcrypt/gpgme/
*** (at least version $NEED_GPGMEPP_VERSION is required).
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

AC_CONFIG_FILES(Makefile src/Makefile)
if test "$qt_version" = "5"; then
    AC_CONFIG_FILES(src/QGpgmeConfig-w32.cmake.in)
    AC_CONFIG_FILES(src/QGpgmeConfig.cmake.in)
    AC_CONFIG_FILES(src/QGpgmeConfigVersion.cmake)
fi
if test "$qt_version" = "6"; then
    AC_CONFIG_FILES(src/QGpgmeQt6Config-w32.cmake.in)
    AC_CONFIG_FILES(src/QGpgmeQt6Config.cmake.in)
    AC_CONFIG_FILES(src/QGpgmeQt6ConfigVersion.cmake)
fi
AC_CONFIG_FILES(tests/Makefile)
AC_CONFIG_FILES(src/qgpgme_version.h)
AM_COND_IF([HAVE_DOXYGEN], [AC_CONFIG_FILES([doc/Doxyfile])])
AC_CONFIG_FILES(doc/Makefile)
AC_OUTPUT

echo "
        QGpgME v${VERSION} has been configured as follows:

        Revision:   mym4_revision  (mym4_revision_dec)
        Qt version: ${qt_version}
        Platform:   $host
"
if test "x${gpg_config_script_warn}" != x; then
cat <<G10EOF
        Mismatches between the target platform and the to
        be used libraries have been been detected for:
         ${gpg_config_script_warn}
        Please check above for warning messages.

G10EOF
fi
