dnl qt6.m4
dnl Copyright (C) 2016 Intevation GmbH
dnl
dnl This file is part of gpgme and is provided under the same license as gpgme

dnl Autoconf macro to find Qt6
dnl
dnl sets GPGME_QT6_LIBS, GPGME_QT6_CFLAGS, and MOC6
dnl
dnl if QT6 was found have_qt6_libs is set to yes

AC_DEFUN([FIND_QT6],
[
  have_qt6_libs="no";

  PKG_CHECK_MODULES(GPGME_QT6,
                    Qt6Core >= 6.4.0,
                    [have_qt6_libs="yes"],
                    [have_qt6_libs="no"])

  PKG_CHECK_MODULES(GPGME_QT6TEST,
                    Qt6Test >= 6.4.0,
                    [have_qt6test_libs="yes"],
                    [have_qt6test_libs="no"])

  if test "$have_qt6_libs" = "yes"; then
    # Qt6 moved moc to libexec
    qt6libexecdir=$($PKG_CONFIG --variable=libexecdir 'Qt6Core >= 6.4.0')
    AC_PATH_TOOL(MOC6, moc, [], [$qt6libexecdir])
    if test -z "$MOC6"; then
      AC_MSG_WARN([moc not found - Qt 6 binding will not be built.])
      have_qt6_libs="no";
    fi
  fi

  if test "$have_qt6_libs" = "yes"; then
    if test "$have_w32_system" != yes; then
      mkspecsdir=$($PKG_CONFIG --variable mkspecsdir Qt6Platform)
      if test -z "$mkspecsdir"; then
        AC_MSG_WARN([Failed to determine Qt's mkspecs directory. Cannot check its build configuration.])
      fi
    fi

    # check if we need -fPIC
    if test -z "$use_reduce_relocations" && test -n "$mkspecsdir"; then
      AC_MSG_CHECKING([whether Qt was built with -fPIC])
      if grep -q "QT_CONFIG .* reduce_relocations" $mkspecsdir/qconfig.pri; then
        use_reduce_relocations="yes"
      else
        use_reduce_relocations="no"
      fi
      AC_MSG_RESULT([$use_reduce_relocations])
    fi
    if test "$use_reduce_relocations" = yes; then
      GPGME_QT6_CFLAGS="$GPGME_QT6_CFLAGS -fPIC"
    fi

    # check if we need -mno-direct-extern-access
    if test "$have_no_direct_extern_access" = yes; then
      if test -z "$use_no_direct_extern_access" && test -n "$mkspecsdir"; then
        AC_MSG_CHECKING([whether Qt was built with -mno-direct-extern-access])
        if grep -q "QT_CONFIG .* no_direct_extern_access" $mkspecsdir/qconfig.pri; then
          use_no_direct_extern_access="yes"
        else
          use_no_direct_extern_access="no"
        fi
        AC_MSG_RESULT([$use_no_direct_extern_access])
      fi
      if test "$use_no_direct_extern_access" = yes; then
        GPGME_QT6_CFLAGS="$GPGME_QT6_CFLAGS -mno-direct-extern-access"
      fi
    fi

    dnl Check that a binary can actually be build with this qt.
    dnl pkg-config may be set up in a way that it looks also for libraries
    dnl of the build system and not only for the host system. In that case
    dnl we check here that we can actually compile / link a qt application
    dnl for host.
    OLDCPPFLAGS=$CPPFLAGS
    OLDLIBS=$LIBS

    CPPFLAGS=$GPGME_QT6_CFLAGS
    LIBS=$GPGME_QT6_LIBS
    AC_LANG_PUSH(C++)
    AC_MSG_CHECKING([whether a simple Qt program can be built])
    AC_LINK_IFELSE([AC_LANG_SOURCE([
      #include <QCoreApplication>
      int main (int argc, char **argv) {
      QCoreApplication app(argc, argv);
      app.exec();
    }])], [have_qt6_libs='yes'], [have_qt6_libs='no'])
    AC_MSG_RESULT([$have_qt6_libs])
    AC_LANG_POP()

    CPPFLAGS=$OLDCPPFLAGS
    LIBS=$OLDLIBS
  fi
])
