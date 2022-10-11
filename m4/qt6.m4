dnl qt6.m4
dnl Copyright (C) 2016 Intevation GmbH
dnl
dnl This file is part of gpgme and is provided under the same license as gpgme

dnl Autoconf macro to find Qt6
dnl
dnl sets GPGME_QT6_LIBS and GPGME_QT6_CFLAGS
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

  if ! test "$have_w32_system" = yes; then
    if "$PKG_CONFIG" --variable qt_config Qt6Core | grep -q "reduce_relocations"; then
      GPGME_QT6_CFLAGS="$GPGME_QT6_CFLAGS -fpic"
    fi
  fi
  if test "$have_qt6_libs" = "yes"; then
    # Qt6 moved moc to libexec
    qt6libexecdir=$($PKG_CONFIG --variable=libexecdir 'Qt6Core >= 6.4.0')
    AC_PATH_TOOL(MOC, moc, [], [$qt6libexecdir])
    AC_MSG_CHECKING([moc version])
    mocversion=`$MOC -v 2>&1`
    mocversiongrep=`echo $mocversion | grep -E "Qt 6|moc 6"`
    if test x"$mocversiongrep" != x"$mocversion"; then
      AC_MSG_RESULT([no])
      # moc was not the qt6 one, try with moc-qt6
      AC_CHECK_TOOL(MOC2, moc-qt6)
      mocversion=`$MOC2 -v 2>&1`
      mocversiongrep=`echo $mocversion | grep -E "Qt 6|moc-qt6 6|moc 6"`
      if test x"$mocversiongrep" != x"$mocversion"; then
        AC_CHECK_TOOL(QTCHOOSER, qtchooser)
        qt6tooldir=`QT_SELECT=qt6 qtchooser -print-env | grep QTTOOLDIR | cut -d '=' -f 2 | cut -d \" -f 2`
        mocversion=`$qt6tooldir/moc -v 2>&1`
        mocversiongrep=`echo $mocversion | grep -E "Qt 6|moc 6"`
        if test x"$mocversiongrep" != x"$mocversion"; then
          # no valid moc found
          have_qt6_libs="no";
        else
          MOC=$qt6tooldir/moc
        fi
      else
        MOC=$MOC2
      fi
    fi
    AC_MSG_RESULT([$mocversion])
    dnl Check that a binary can actually be build with this qt.
    dnl pkg-config may be set up in a way that it looks also for libraries
    dnl of the build system and not only for the host system. In that case
    dnl we check here that we can actually compile / link a qt application
    dnl for host.
    OLDCPPFLAGS=$CPPFLAGS
    CPPFLAGS=$GPGME_QT6_CFLAGS
    OLDLIBS=$LIBS
    LIBS=$GPGME_QT6_LIBS
    AC_LANG_PUSH(C++)
    AC_MSG_CHECKING([whether a simple qt program can be built])
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
