dnl qt.m4
dnl Copyright (C) 2016 Intevation GmbH
dnl
dnl This file is part of gpgme and is provided under the same license as gpgme

dnl Autoconf macro to find either Qt4 or Qt5
dnl
dnl sets GPGME_QT_LIBS and GPGME_QT_CFLAGS
dnl
dnl if QT5 was found have_qt5_libs is set to yes

AC_DEFUN([FIND_QT],
[
  have_qt5_libs="no";

  PKG_CHECK_MODULES(GPGME_QT,
                    Qt5Core >= 5.0.0,
                    [have_qt5_libs="yes"],
                    [have_qt5_libs="no"])

  if "$PKG_CONFIG" --variable qt_config Qt5Core | grep -q "reduce_relocations"; then
    GPGME_QT_CFLAGS="$GPGME_QT_CFLAGS -fpic"
  fi
  if test "$have_qt5_libs" = "yes"; then
    AC_CHECK_TOOL(MOC, moc)
    AC_MSG_CHECKING([moc version])
    mocversion=`$MOC -v 2>&1`
    mocversiongrep=`echo $mocversion | grep "Qt 5\|moc 5"`
    if test x"$mocversiongrep" != x"$mocversion"; then
      AC_MSG_RESULT([no])
      # moc was not the qt5 one, try with moc-qt5
      AC_CHECK_TOOL(MOC2, moc-qt5)
      mocversion=`$MOC2 -v 2>&1`
      mocversiongrep=`echo $mocversion | grep "Qt 5\|moc-qt5 5\|moc 5"`
      if test x"$mocversiongrep" != x"$mocversion"; then
        AC_CHECK_TOOL(QTCHOOSER, qtchooser)
        qt5tooldir=`QT_SELECT=qt5 qtchooser -print-env | grep QTTOOLDIR | cut -d '=' -f 2 | cut -d \" -f 2`
        mocversion=`$qt5tooldir/moc -v 2>&1`
        mocversiongrep=`echo $mocversion | grep "Qt 5\|moc 5"`
        if test x"$mocversiongrep" != x"$mocversion"; then
          # no valid moc found
          have_qt5_libs="no";
        else
          MOC=$qt5tooldir/moc
        fi
      else
        MOC=$MOC2
      fi
    fi
  fi
])
